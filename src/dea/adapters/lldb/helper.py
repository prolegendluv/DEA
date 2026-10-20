"""Isolated LLDB SB API host. Requires only the stdlib and matching LLDB bindings.

Executed by absolute path with -I; never imports DEA or the server's Pydantic ABI.
"""
import argparse
import base64
import hashlib
import importlib.util
import os
from pathlib import Path
import socket
import sys
import threading

_spec = importlib.util.spec_from_file_location("_dea_lldb_protocol", Path(__file__).with_name("protocol.py"))
protocol = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(protocol)


class DebugError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def check(error, code="INVALID_REQUEST"):
    if error.Fail():
        raise DebugError(code)


class Engine:
    """Native objects stay here. Command and event threads share a short SB API lock."""
    def __init__(self, lldb, send, session_id):
        self.lldb, self.send, self.session_id = lldb, send, session_id
        self.debugger = lldb.SBDebugger.Create(False)  # Disable debugger init files.
        self.debugger.SetAsync(True)
        self.listener = lldb.SBListener("dea-process-events")
        self.target = self.process = None
        self.attached = False
        self.lock = threading.RLock()
        self.stopping = threading.Event()
        self.event_id = 0
        self.last_stop = None
        self.last_state = None
        self.entry_pending = self.interrupt_pending = False
        self.selected_index = 0
        self.thread = threading.Thread(target=self.listen, name="dea-lldb-listener", daemon=True)
        self.thread.start()

    def emit(self, kind, **fields):
        with self.lock:
            self.event_id += 1
            if self.event_id > 2**63 - 1:
                raise DebugError("RESOURCE_LIMIT")
            body = dict(event_id=self.event_id, kind=kind, **fields)
            self.send(protocol.envelope("event", "debugger_event", self.event_id, body))

    def selected_thread(self):
        self.require_stopped()
        thread = self.process.GetSelectedThread()
        if not thread.IsValid():
            if self.process.GetNumThreads() == 0:
                raise DebugError("INVALID_STATE")
            thread = self.process.GetThreadAtIndex(0)
        return thread

    def require_stopped(self):
        if self.process is None or not self.process.IsValid() or self.process.GetState() not in (
                self.lldb.eStateStopped, self.lldb.eStateCrashed, self.lldb.eStateSuspended):
            raise DebugError("INVALID_STATE")

    def _target(self, path):
        target = self.debugger.CreateTarget(path or "")
        if not target.IsValid():
            raise DebugError("INVALID_REQUEST")
        self.target = target

    def start(self, body):
        if self.process is not None:
            raise DebugError("INVALID_STATE")
        if body["backend"] != "lldb" or body.get("io_mode", "capture") != "capture":
            raise DebugError("CAPABILITY_UNAVAILABLE")
        self._target(body["binary_path"])
        info = self.lldb.SBLaunchInfo(body.get("args", []))
        flags = info.GetLaunchFlags()
        flags &= ~getattr(self.lldb, "eLaunchFlagLaunchInTTY", 0)
        flags &= ~getattr(self.lldb, "eLaunchFlagDisableSTDIO", 0)
        if body.get("stop_at_entry", True):
            flags |= self.lldb.eLaunchFlagStopAtEntry
            self.entry_pending = True
        else:
            flags &= ~self.lldb.eLaunchFlagStopAtEntry
        info.SetLaunchFlags(flags)
        info.SetListener(self.listener)  # Subscribe before launch; immediate stop cannot be lost.
        info.SetShellExpandArguments(False)
        if body.get("cwd"):
            info.SetWorkingDirectory(body["cwd"])
        env = {key: value for key, value in os.environ.items() if not key.startswith("DEA_CONTROL_")}
        for entry in body.get("env", []):
            if entry["key"].startswith("DEA_CONTROL_"):
                continue
            if os.name == "nt":
                for key in tuple(env):
                    if key.casefold() == entry["key"].casefold():
                        del env[key]
            env[entry["key"]] = entry["value"]
        info.SetEnvironmentEntries([key + "=" + value for key, value in env.items()], False)
        info.AddOpenFileAction(0, os.devnull, True, False)
        error = self.lldb.SBError()
        self.process = self.target.Launch(info, error)
        check(error, "CAPABILITY_UNAVAILABLE")
        if not self.process.IsValid():
            raise DebugError("CAPABILITY_UNAVAILABLE")
        self.emit("started")

    def attach(self, body):
        if self.process is not None:
            raise DebugError("INVALID_STATE")
        if body["backend"] != "lldb":
            raise DebugError("INVALID_REQUEST")
        self._target(body.get("binary_path"))
        self.attached = True
        info = self.lldb.SBAttachInfo(body["pid"])
        info.SetListener(self.listener)
        error = self.lldb.SBError()
        self.process = self.target.Attach(info, error)
        check(error, "CAPABILITY_UNAVAILABLE")
        if not self.process.IsValid():
            raise DebugError("CAPABILITY_UNAVAILABLE")
        # A helper failure must release an external process rather than terminate it.
        if hasattr(self.process, "SetDetachKeepsStopped"):
            self.process.SetDetachKeepsStopped(False)
        self.emit("started")

    def breakpoint(self, body):
        self.require_stopped()
        location = body["location"]
        file, colon, number = location.rpartition(":")
        if colon and number.isdecimal() and int(number) > 0:
            bp = self.target.BreakpointCreateByLocation(file, int(number))
        else:
            bp = self.target.BreakpointCreateByName(location)
        if not bp.IsValid():
            raise DebugError("INVALID_REQUEST")
        if body.get("condition") is not None:
            bp.SetCondition(body["condition"])
        return {"breakpoint_id": str(bp.GetID()), "verified": bp.GetNumLocations() > 0}

    def location(self, frame):
        result = {}
        line = frame.GetLineEntry()
        if line.IsValid():
            file = line.GetFileSpec()
            path = os.path.join(file.GetDirectory() or "", file.GetFilename() or "")
            if path:
                result["file"] = path
                if line.GetLine() > 0:
                    result["line"] = line.GetLine()
        function = frame.GetFunctionName()
        if function:
            result["function"] = function
        address = frame.GetPC()
        if 0 <= address < 2**64 - 1:
            result["address"] = address
        if not result:
            result["function"] = "<unknown>"
        return result

    def frame_identity(self, thread, frame):
        # CFA identifies invocation; function path disambiguates inlined frames.
        function = hashlib.sha256((frame.GetFunctionName() or "?").encode("utf-8")).hexdigest()[:24]
        return "thread:{}/cfa:{:x}/frame:{}:{}".format(
            thread.GetThreadID(), frame.GetCFA(), frame.GetFrameID(), function)

    def value(self, value, identity, name):
        if len(name) > 4096:
            raise DebugError("RESOURCE_LIMIT")
        if len(identity) > 4096:
            identity = "value:" + hashlib.sha256(identity.encode("utf-8")).hexdigest()
        value = value.GetNonSyntheticValue()
        result = {"identity": identity, "name": name, "available": False, "value": None}
        if not value.IsValid() or value.GetError().Fail():
            return result
        scalar = value.GetValue()  # No GetSummary(), synthetic provider, or target repr call.
        if scalar is None:
            data = value.GetData()
            length = data.GetByteSize()
            if length > 262144:
                raise DebugError("RESOURCE_LIMIT")
            error = self.lldb.SBError()
            raw = data.ReadRawData(error, 0, length)
            if error.Fail() or raw is None:
                return result
            if isinstance(raw, str):
                raw = raw.encode("latin1")
            if len(raw) != length:
                return result
            scalar = "{}:0x{}".format(value.GetTypeName() or "<data>", bytes(raw).hex())
        if len(scalar) > 1048576:
            raise DebugError("RESOURCE_LIMIT")
        result.update(value=scalar, available=True)
        return result

    def frame(self, index, depth):
        thread = self.selected_thread()
        if index >= thread.GetNumFrames():
            raise DebugError("INVALID_REQUEST")
        frame = thread.GetFrameAtIndex(index)
        self.selected_index = index
        self.process.SetSelectedThread(thread)
        thread.SetSelectedFrame(index)
        identity = self.frame_identity(thread, frame)
        values = frame.GetVariables(True, True, False, True, self.lldb.eNoDynamicValues)
        variables = []
        complete = values.GetSize() <= 4096
        for index in range(min(values.GetSize(), 4096)):
            value = values.GetValueAtIndex(index)
            name = value.GetName() or "<unnamed>"
            address = value.GetLoadAddress()
            key = "{}/local:{}:{:x}".format(identity, name, address)
            variables.append(self.value(value, key, name))
            if depth:
                self.children(value, key, name, depth, variables)
        return dict(index=frame.GetFrameID(), identity=identity, location=self.location(frame),
                    variables=variables, variables_complete=complete)

    def children(self, value, identity, name, depth, result):
        value = value.GetNonSyntheticValue()
        count = value.GetNumChildren(4097)
        if count > 4096 or len(result) + count > 4096:
            raise DebugError("RESOURCE_LIMIT")
        for index in range(count):
            child = value.GetChildAtIndex(index, self.lldb.eNoDynamicValues, False)
            child_name = name + "." + (child.GetName() or str(index))
            child_identity = identity + "/child:" + str(index)
            result.append(self.value(child, child_identity, child_name))
            if depth > 1:
                self.children(child, child_identity, child_name, depth - 1, result)

    def memory(self, body):
        self.require_stopped()
        error = self.lldb.SBError()
        data = self.process.ReadMemory(body["address"], body["size"], error)
        check(error)
        if isinstance(data, str):
            data = data.encode("latin1")
        if data is None or len(data) != body["size"]:
            raise DebugError("INVALID_REQUEST")
        return {"region": body, "data": base64.urlsafe_b64encode(data).decode("ascii")}

    def snapshot(self, body):
        thread = self.selected_thread()
        frame = self.frame(body.get("frame_index", 0), body.get("max_depth", 1))
        frames = [self.frame(index, 0) for index in range(min(thread.GetNumFrames(), 128))]
        thread.SetSelectedFrame(body.get("frame_index", 0))
        self.selected_index = body.get("frame_index", 0)
        native = thread.GetFrameAtIndex(self.selected_index)
        registers = []
        register_sets = native.GetRegisters()
        for index in range(register_sets.GetSize()):
            group = register_sets.GetValueAtIndex(index)
            if group.GetNumChildren() > 4096:
                raise DebugError("RESOURCE_LIMIT")
            for child_index in range(group.GetNumChildren()):
                value = group.GetChildAtIndex(child_index)
                name = value.GetName() or str(child_index)
                identity = "thread:{}/register:{}/{}".format(thread.GetThreadID(), index, name)
                registers.append(self.value(value, identity, name))
        return dict(session_id=self.session_id, stop_id=body["stop_id"],
                    thread_id=thread.GetThreadID(), frame_context=frame["identity"],
                    reason=body["reason"], location=frame["location"], registers=registers,
                    variables=frame["variables"], frames=frames,
                    memory=[self.memory(region) for region in body.get("memory_regions", [])],
                    registers_complete=True, variables_complete=frame["variables_complete"],
                    frames_complete=thread.GetNumFrames() <= 128)

    def dispatch(self, operation, body, request_id):
        with self.lock:
            ack = {"request_id": request_id, "accepted": True}
            if operation == "session_start":
                self.start(body)
            elif operation == "session_attach":
                self.attach(body)
            elif operation == "breakpoint_set":
                return self.breakpoint(body)
            elif operation == "execution_continue":
                self.require_stopped()
                check(self.process.Continue(), "INVALID_STATE")
            elif operation == "execution_step":
                thread = self.selected_thread()
                mode = body["mode"]
                if mode == "over":
                    thread.StepOver(self.lldb.eOnlyThisThread)
                elif mode == "into":
                    thread.StepInto(self.lldb.eOnlyThisThread)
                elif mode == "out":
                    thread.StepOut()
                else:
                    raise DebugError("INVALID_REQUEST")
            elif operation == "execution_interrupt":
                if self.process is None:
                    raise DebugError("INVALID_STATE")
                self.interrupt_pending = True
                check(self.process.Stop(), "INVALID_STATE")
            elif operation == "snapshot_capture":
                return self.snapshot(body)
            elif operation == "state_inspect_frame":
                return self.frame(body["frame_index"], body["max_depth"])
            elif operation == "state_eval_expression":
                thread = self.selected_thread()
                frame = thread.GetFrameAtIndex(self.selected_index)
                options = self.lldb.SBExpressionOptions()
                options.SetTimeoutInMicroSeconds(1000000)
                options.SetTryAllThreads(False)
                options.SetFetchDynamicValue(self.lldb.eNoDynamicValues)
                value = frame.EvaluateExpression(body["expr"], options)
                check(value.GetError())
                return self.value(value, self.frame_identity(thread, frame) + "/eval:" + body["expr"], body["expr"])
            elif operation == "state_read_memory":
                return self.memory(body)
            elif operation == "session_terminate":
                if self.process is not None and self.process.IsValid():
                    if body["policy"] == "detach":
                        check(self.process.Detach(), "DETACH_FAILED")
                    elif self.attached:
                        raise DebugError("INVALID_REQUEST")
                    elif self.process.GetState() not in (self.lldb.eStateExited, self.lldb.eStateDetached):
                        check(self.process.Kill(), "INVALID_STATE")
                return {}
            else:
                raise DebugError("PROTOCOL_ERROR")
            return ack

    def output(self, process):
        for getter, stream in ((process.GetSTDOUT, sys.stdout), (process.GetSTDERR, sys.stderr)):
            for _ in range(64):
                text = getter(16384)
                if not text:
                    break
                if hasattr(stream, "buffer"):
                    stream.buffer.write(text if isinstance(text, bytes) else text.encode("utf-8", "replace"))
                    stream.buffer.flush()
                else:
                    stream.write(text)
                    stream.flush()

    def listen(self):
        try:
            while not self.stopping.is_set():
                event = self.lldb.SBEvent()
                if not self.listener.WaitForEvent(1, event):
                    continue
                if not self.lldb.SBProcess.EventIsProcessEvent(event):
                    continue
                process = self.lldb.SBProcess.GetProcessFromEvent(event)
                with self.lock:
                    self.output(process)
                    state = self.lldb.SBProcess.GetStateFromEvent(event)
                    if self.lldb.SBProcess.GetRestartedFromEvent(event):
                        continue
                    if state in (self.lldb.eStateRunning, self.lldb.eStateStepping):
                        if self.last_state != "running":
                            self.emit("running")
                            self.last_state = "running"
                    elif state in (self.lldb.eStateStopped, self.lldb.eStateCrashed, self.lldb.eStateSuspended):
                        stop_key = (process.GetProcessID(), process.GetStopID())
                        if stop_key == self.last_stop:
                            continue
                        self.last_stop = stop_key
                        self.last_state = "stopped"
                        # Choose the thread that caused the event rather than an arbitrary frame.
                        thread = process.GetSelectedThread()
                        for index in range(process.GetNumThreads()):
                            candidate = process.GetThreadAtIndex(index)
                            if candidate.GetStopReason() not in (self.lldb.eStopReasonNone, self.lldb.eStopReasonInvalid):
                                thread = candidate
                                process.SetSelectedThread(thread)
                                break
                        reason = self.reason(thread)
                        self.emit("stopped", reason=reason, thread_id=thread.GetThreadID())
                    elif state == self.lldb.eStateExited and self.last_state != "exited":
                        self.last_state = "exited"
                        self.emit("exited", exit_code=process.GetExitStatus())
        except Exception:
            if not self.stopping.is_set():
                try:
                    self.emit("failed", error_code="PROTOCOL_ERROR")
                except Exception:
                    pass
                self.stopping.set()

    def reason(self, thread):
        reason = thread.GetStopReason()
        if self.entry_pending:
            self.entry_pending = False
            return "entry"
        mapping = {self.lldb.eStopReasonBreakpoint: "breakpoint",
                   self.lldb.eStopReasonWatchpoint: "watchpoint",
                   self.lldb.eStopReasonPlanComplete: "step",
                   self.lldb.eStopReasonException: "exception"}
        if reason in mapping:
            self.entry_pending = False
            self.interrupt_pending = False
            return mapping[reason]
        if self.interrupt_pending:
            self.interrupt_pending = False
            return "interrupt"
        return "signal" if reason == self.lldb.eStopReasonSignal else "interrupt"

    def close(self):
        self.stopping.set()
        self.thread.join(2)
        if self.thread.is_alive():
            raise DebugError("COMMAND_TIMEOUT")
        with self.lock:
            if self.process is not None and self.process.IsValid():
                state = self.process.GetState()
                if state not in (self.lldb.eStateExited, self.lldb.eStateDetached):
                    if self.attached:
                        check(self.process.Detach(), "DETACH_FAILED")
                    else:
                        check(self.process.Kill(), "INVALID_STATE")
            self.lldb.SBDebugger.Destroy(self.debugger)


def serve(lldb, connection, session_id):
    engine = Engine(lldb, connection.send, session_id)
    previous = 1
    try:
        while True:
            message = connection.receive()
            if message["kind"] != "request" or message["request_id"] <= previous:
                raise protocol.ProtocolError("Nonmonotonic request")
            previous = message["request_id"]
            operation = message["operation"]
            try:
                body = protocol.validate(message)
                protocol.validate_request(operation, body)
                result = engine.dispatch(operation, body, previous)
                response = protocol.envelope("response", operation, previous, result)
                # Bound including JSON escaping; never send a partial oversized response.
                try:
                    protocol.frame(response, connection.maximum)
                except protocol.ProtocolError:
                    raise DebugError("RESOURCE_LIMIT")
            except DebugError as exc:
                response = protocol.envelope("response", "error", previous, {"code": exc.code})
            except protocol.ProtocolError:
                response = protocol.envelope("response", "error", previous, {"code": "PROTOCOL_ERROR"})
            except (KeyError, ValueError, TypeError):
                response = protocol.envelope("response", "error", previous, {"code": "INVALID_REQUEST"})
            connection.send(response)
            if operation == "session_terminate" and response["operation"] != "error":
                return
    except EOFError:
        pass
    finally:
        engine.close()


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--probe", action="store_true")
    parser.add_argument("--module-path")
    parser.add_argument("--session-id")
    parser.add_argument("--max-bytes", type=int, default=1048576)
    args = parser.parse_args(argv)
    if args.module_path:
        sys.path.insert(0, args.module_path)
    try:
        import lldb
        lldb.SBDebugger.Initialize()
        # Ensure the extension loads, not just the top-level Python namespace.
        debugger = lldb.SBDebugger.Create(False)
        debugger.SetAsync(True)
        if not debugger.IsValid():
            raise RuntimeError("LLDB initialization failed")
        lldb.SBDebugger.Destroy(debugger)
    except Exception:
        if args.probe:
            print('{"available":false}')
        return 2
    if args.probe:
        print('{"available":true}')
        lldb.SBDebugger.Terminate()
        return 0
    connection = None
    try:
        host = os.environ.pop("DEA_CONTROL_HOST")
        port = int(os.environ.pop("DEA_CONTROL_PORT"))
        token = os.environ.pop("DEA_CONTROL_TOKEN")
        if host not in ("127.0.0.1", "::1"):
            raise protocol.ProtocolError("Control is loopback-only")
        sock = socket.create_connection((host, port), timeout=10)
        connection = protocol.Connection(sock, args.max_bytes)
        connection.send(protocol.envelope("request", "hello", 1, {"token": token}))
        reply = connection.receive()
        if reply != protocol.envelope("response", "hello", 1, {}):
            raise protocol.ProtocolError("Authentication rejected")
        del token
        sock.settimeout(None)
        serve(lldb, connection, args.session_id)
        return 0
    finally:
        if connection:
            connection.close()
        lldb.SBDebugger.Terminate()


if __name__ == "__main__":
    raise SystemExit(main())
