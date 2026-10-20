"""Isolated stdlib PDB engine. Control bytes never use target file descriptors."""
from __future__ import annotations

import ast
import bdb
import io
import json
import linecache
import os
import pdb
import queue
import socket
import struct
import sys
import threading
import tokenize
import types
from pathlib import Path

from dea.contracts.models import (
    Breakpoint, BreakpointSpec, CaptureRequest, CommandAck, DebuggerEvent, DeaError,
    ErrorCode, HelperMessage, LaunchSpec, RawFrame, RawSnapshot, RawValue,
    SourceLocation, StepMode, StopReason,
)


def receive(sock, count):
    data = bytearray()
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part:
            raise EOFError
        data.extend(part)
    return bytes(data)


class Channel:
    def __init__(self, sock, limit=1_048_576):
        self.sock, self.limit = sock, limit
        self.lock = threading.Lock()

    def read(self):
        size = struct.unpack('!I', receive(self.sock, 4))[0]
        if not 1 <= size <= self.limit:
            raise ValueError('Invalid frame size')
        return HelperMessage.model_validate_json(receive(self.sock, size))

    def send(self, message):
        data = message.model_dump_json(exclude_none=True).encode('utf-8')
        if not 1 <= len(data) <= self.limit:
            raise DeaError(ErrorCode.RESOURCE_LIMIT)
        with self.lock:
            self.sock.sendall(struct.pack('!I', len(data)) + data)

    def reply(self, message, result=None, error=None):
        body = {'code': error.value} if error else result
        raw = body.model_dump_json() if hasattr(body, 'model_dump_json') else json.dumps(body or {}, allow_nan=False)
        try:
            self.send(HelperMessage(kind='response', request_id=message.request_id,
                                    operation='error' if error else message.operation, body_json=raw))
        except (DeaError, ValueError):
            if error:
                raise
            self.reply(message, error=ErrorCode.HISTORY_UNAVAILABLE)


def safe_value(value, depth=0, seen=None):
    """Never call target-defined repr, descriptors, iteration, or truth methods."""
    typ = type(value)
    if typ in (str, int, float, bool, bytes, complex, type(None)):
        try:
            text = repr(value)
        except (ValueError, OverflowError):
            raise ValueError('Builtin representation unavailable')
        return text
    if typ in (list, tuple, dict, set, frozenset) and depth < 3:
        seen = set() if seen is None else seen
        if id(value) in seen:
            raise ValueError('Cyclic container has no finite exact representation')
        seen.add(id(value))
        try:
            if len(value) > 1000:
                raise ValueError('Container exceeds safe capture bound')
            if typ is dict:
                parts = [safe_value(k, depth+1, seen) + ': ' + safe_value(v, depth+1, seen) for k, v in value.items()]
                return '{' + ', '.join(parts) + '}'
            parts = [safe_value(v, depth+1, seen) for v in value]
            if typ is tuple:
                return '(' + ', '.join(parts) + (',' if len(parts) == 1 else '') + ')'
            if typ is list:
                return '[' + ', '.join(parts) + ']'
            return typ.__name__ + '(' + ', '.join(parts) + ')'
        finally:
            seen.remove(id(value))
    raise ValueError('Non-executing exact representation unavailable')


class StructuredPdb(pdb.Pdb):
    def __init__(self, channel, session_id, capacity=256):
        kwargs = dict(stdin=io.StringIO(), stdout=io.StringIO(), readrc=False, nosigint=True)
        if sys.version_info >= (3, 14):
            kwargs['backend'] = 'settrace'
        super().__init__(**kwargs)
        self.channel, self.session_id = channel, session_id
        self.launched = False
        self.commands = queue.Queue(capacity)
        self.interrupted = threading.Event()
        self.terminated = threading.Event()
        self.current = None
        self.running = False
        self.event_id = 0
        self._first = True
        self._stop_at_entry = True
        self._frame_ids = {}
        self._frame_counter = 0
        self._script = ''
        self._functions = {}
        self._pending_function_breaks = []

    def event(self, kind, reason=None, exit_code=None, error_code=None):
        self.event_id += 1
        event = DebuggerEvent(event_id=self.event_id, kind=kind, reason=reason,
                              thread_id=1 if kind == 'stopped' else None,
                              exit_code=exit_code, error_code=error_code)
        self.channel.send(HelperMessage(kind='event', event_id=self.event_id,
                                        operation='debugger_event', body_json=event.model_dump_json()))

    def reader(self):
        try:
            while not self.terminated.is_set():
                message = self.channel.read()
                if message.kind != 'request' or message.request_id < 2:
                    raise ValueError('Invalid request')
                if message.operation == 'execution_interrupt':
                    if json.loads(message.body_json) != {} or not self.running:
                        self.channel.reply(message, error=ErrorCode.INVALID_STATE)
                    else:
                        self.interrupted.set()
                        self.channel.reply(message, CommandAck(request_id=message.request_id))
                elif message.operation == 'session_terminate':
                    body = json.loads(message.body_json)
                    if body != {'policy': 'terminate_owned'}:
                        self.channel.reply(message, error=ErrorCode.CAPABILITY_UNAVAILABLE)
                        continue
                    self.terminated.set()
                    self.channel.reply(message)
                    self.commands.put_nowait(message)
                    return
                else:
                    if self.launched and self.running:
                        self.channel.reply(message, error=ErrorCode.INVALID_STATE)
                        continue
                    try:
                        self.commands.put_nowait(message)
                    except queue.Full:
                        self.event('failed', error_code=ErrorCode.CONTROL_OVERFLOW)
                        self.terminated.set()
                        return
        except (EOFError, OSError, ValueError):
            self.terminated.set()
            try:
                self.commands.put_nowait(None)
            except queue.Full:
                pass

    def trace_dispatch(self, frame, event, arg):
        if self.terminated.is_set():
            raise bdb.BdbQuit
        return super().trace_dispatch(frame, event, arg)

    def dispatch_call(self, frame, arg):
        if self.botframe is None:
            self.botframe = frame.f_back
        return self.trace_dispatch  # keep every Python frame interruptible

    def dispatch_line(self, frame):
        self.currentbp = None
        if self.interrupted.is_set():
            self.interrupted.clear()
            self.stop(frame, StopReason.INTERRUPT)
        else:
            breakpoint_hit = self.break_here(frame)
            if not (self.stop_here(frame) or breakpoint_hit):
                return self.trace_dispatch
            if not (getattr(self, 'cmdframe', None) is frame and getattr(self, 'cmdlineno', None) == frame.f_lineno):
                self.user_line(frame)
            return self.trace_dispatch
        return self.trace_dispatch

    def dispatch_exception(self, frame, arg):
        # CPython's generator exhaustion is not a target exception stop.
        if arg[0] not in (StopIteration, GeneratorExit, SystemExit):
            self.stop(frame, StopReason.EXCEPTION)
        return self.trace_dispatch

    def dispatch_return(self, frame, arg):
        try:
            return super().dispatch_return(frame, arg)
        finally:
            self._frame_ids.pop(id(frame), None)

    def user_line(self, frame):
        if self._first:
            self._first = False
            if not self._stop_at_entry:
                self.set_continue()
                return
            reason = StopReason.ENTRY
        else:
            reason = StopReason.BREAKPOINT if getattr(self, 'currentbp', None) else StopReason.STEP
        self.stop(frame, reason)

    def user_return(self, frame, return_value):
        if frame.f_back is self.botframe:
            return
        self.stop(frame, StopReason.STEP)

    def set_continue(self):
        # bdb's default disables tracing without breakpoints, preventing interruption.
        self._set_stopinfo(self.botframe, None, -1)

    def frame_identity(self, frame):
        key = id(frame)
        if key not in self._frame_ids:
            self._frame_counter += 1
            # Retain identity without retaining frame locals after execution.
            self._frame_ids[key] = str(self._frame_counter)
        return 'thread:1/frame:' + self._frame_ids[key]

    def frames(self):
        frames, frame = [], self.current
        while frame is not None and frame is not self.botframe:
            frames.append(frame)
            frame = frame.f_back
        return frames

    def observe(self, frame, index):
        identity = self.frame_identity(frame)
        values = []
        complete = True
        for name, value in sorted(frame.f_locals.copy().items()):
            if not isinstance(name, str) or len(identity + '/local:' + name) > 4096:
                complete = False
                continue
            try:
                text = safe_value(value)
                values.append(RawValue(identity=identity + '/local:' + name, name=name, value=text))
            except ValueError:
                values.append(RawValue(identity=identity + '/local:' + name, name=name, available=False))
        return RawFrame(index=index, identity=identity,
                        location=SourceLocation(file=frame.f_code.co_filename, line=frame.f_lineno,
                                                function=frame.f_code.co_name),
                        variables=tuple(values), variables_complete=complete)

    def handle(self, message):
        op, body = message.operation, json.loads(message.body_json)
        if op == 'breakpoint_set':
            spec = BreakpointSpec.model_validate_json(message.body_json)
            location = spec.location
            filename, sep, number = location.rpartition(':')
            funcname = None
            if sep and number.isdecimal():
                filename, lineno = self.canonic(filename), int(number)
            else:
                definition = self._functions.get(location)
                if definition is None:
                    raise DeaError(ErrorCode.INVALID_REQUEST)
                filename, lineno, funcname = definition
                filename = self.canonic(filename)
            if lineno <= 0 or not linecache.getline(filename, lineno):
                raise DeaError(ErrorCode.INVALID_REQUEST)
            error = self.set_break(filename, lineno, cond=spec.condition, funcname=funcname)
            if error:
                raise DeaError(ErrorCode.INVALID_REQUEST)
            bp = bdb.Breakpoint.bplist[filename, lineno][-1]
            return Breakpoint(breakpoint_id=str(bp.number), verified=True)
        if op in ('execution_continue', 'execution_step'):
            if op == 'execution_continue':
                if body != {}:
                    raise DeaError(ErrorCode.INVALID_REQUEST)
                self.set_continue()
            else:
                if set(body) != {'mode'}:
                    raise DeaError(ErrorCode.INVALID_REQUEST)
                mode = StepMode(body['mode'])
                if mode is StepMode.OVER:
                    self.set_next(self.current)
                elif mode is StepMode.INTO:
                    self.set_step()
                else:
                    self.set_return(self.current)
            self.running = True
            self.channel.reply(message, CommandAck(request_id=message.request_id))
            self.event('running')
            return 'resume'
        if op == 'snapshot_capture':
            request = CaptureRequest.model_validate_json(message.body_json)
            if request.memory_regions:
                raise DeaError(ErrorCode.CAPABILITY_UNAVAILABLE)
            frames = tuple(self.observe(f, i) for i, f in enumerate(self.frames()))
            if request.frame_index >= len(frames):
                raise DeaError(ErrorCode.INVALID_REQUEST)
            selected = frames[request.frame_index]
            return RawSnapshot(session_id=self.session_id, stop_id=request.stop_id,
                                thread_id=1, frame_context=selected.identity, reason=request.reason,
                                location=selected.location, variables=selected.variables,
                                frames=frames, frames_complete=True,
                                variables_complete=selected.variables_complete)
        if op == 'state_inspect_frame':
            if set(body) != {'frame_index', 'max_depth'} or type(body['frame_index']) is not int or type(body['max_depth']) is not int:
                raise DeaError(ErrorCode.INVALID_REQUEST)
            if not 0 <= body['max_depth'] <= 8 or not 0 <= body['frame_index'] < len(self.frames()):
                raise DeaError(ErrorCode.INVALID_REQUEST)
            return self.observe(self.frames()[body['frame_index']], body['frame_index'])
        if op == 'state_eval_expression':
            if set(body) != {'expr'} or type(body['expr']) is not str or not 1 <= len(body['expr']) <= 4096:
                raise DeaError(ErrorCode.INVALID_REQUEST)
            value = eval(body['expr'], self.current.f_globals, self.current.f_locals)
            try:
                return RawValue(identity=self.frame_identity(self.current) + '/eval', name=body['expr'], value=safe_value(value))
            except ValueError:
                return RawValue(identity=self.frame_identity(self.current) + '/eval', name=body['expr'], available=False)
        raise DeaError(ErrorCode.CAPABILITY_UNAVAILABLE)

    def stop(self, frame, reason):
        self.running = False
        self.current = frame
        self.event('stopped', reason=reason)
        while not self.terminated.is_set():
            message = self.commands.get()
            if message is None or self.terminated.is_set():
                raise bdb.BdbQuit
            try:
                result = self.handle(message)
                if result == 'resume':
                    self.current = None
                    return
                self.channel.reply(message, result)
            except DeaError as exc:
                self.channel.reply(message, error=exc.code)
            except Exception:
                self.channel.reply(message, error=ErrorCode.INVALID_REQUEST)
        raise bdb.BdbQuit

    def launch(self, message):
        spec = LaunchSpec.model_validate_json(message.body_json)
        if spec.io_mode != 'capture' or spec.memory_regions:
            raise DeaError(ErrorCode.CAPABILITY_UNAVAILABLE)
        path = Path(spec.binary_path).resolve()
        if spec.cwd:
            os.chdir(spec.cwd)
        for entry in spec.env:
            os.environ[entry.key] = entry.value
        for key in list(os.environ):
            if key.startswith('DEA_CONTROL_') or key.startswith('DEA_PDB_'):
                del os.environ[key]
        sys.argv[:] = [str(path), *spec.args]
        sys.path.insert(0, str(path.parent))
        with tokenize.open(path) as source:
            text = source.read()
        tree = ast.parse(text, str(path))
        def functions(nodes, prefix=''):
            for node in nodes:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    name = prefix + node.name
                    if not isinstance(node, ast.ClassDef):
                        self._functions[name] = (str(path), node.lineno, node.name)
                        self._functions.setdefault(node.name, (str(path), node.lineno, node.name))
                    functions(node.body, name + '.')
        functions(tree.body)
        code = compile(tree, str(path), 'exec')
        self.launched = True
        self._script = str(path)
        self._stop_at_entry = spec.stop_at_entry
        target_module = types.ModuleType('__main__')
        globals_ = target_module.__dict__
        globals_.update({'__file__': str(path), '__builtins__': __builtins__, '__package__': None})
        sys.modules['__main__'] = target_module
        self.channel.reply(message, CommandAck(request_id=message.request_id))
        self.event('started')
        self.running = True
        exit_code = 0
        try:
            self.run(code, globals_, globals_)
        except SystemExit as exc:
            exit_code = exc.code if type(exc.code) is int else (0 if exc.code is None else 1)
        except BaseException:
            exit_code = 1
        finally:
            self.current = None
            self.running = False
            self.event('exited', exit_code=max(-(2**31), min(exit_code, 2**32-1)))
            self._frame_ids.clear()


def main():
    host, port, token = (os.environ.pop(name) for name in ('DEA_CONTROL_HOST', 'DEA_CONTROL_PORT', 'DEA_CONTROL_TOKEN'))
    sid = os.environ.pop('DEA_PDB_SESSION_ID')
    capacity = int(os.environ.pop('DEA_PDB_CAPACITY', '256'))
    limit = int(os.environ.pop('DEA_PDB_PROTOCOL_BYTES', '1048576'))
    sock = socket.create_connection((host, int(port)), timeout=10)
    sock.settimeout(None)
    channel = Channel(sock, limit)
    channel.send(HelperMessage(kind='request', request_id=1, operation='hello', body_json=json.dumps({'token': token})))
    hello = channel.read()
    if hello.kind != 'response' or hello.request_id != 1 or hello.operation != 'hello' or json.loads(hello.body_json) != {}:
        return 2
    engine = StructuredPdb(channel, sid, capacity)
    thread = threading.Thread(target=engine.reader, daemon=True, name='dea-pdb-control')
    thread.start()
    try:
        message = engine.commands.get()
        if message is None or message.operation != 'session_start':
            raise DeaError(ErrorCode.INVALID_REQUEST)
        engine.launch(message)
    except DeaError as exc:
        channel.reply(message, error=exc.code)
    except Exception:
        channel.reply(message, error=ErrorCode.INVALID_REQUEST)
    finally:
        engine.terminated.set()
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()
        thread.join(timeout=1)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
