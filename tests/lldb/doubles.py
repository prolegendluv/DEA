"""Deterministic LLDB SB objects with real asynchronous event delivery."""
import queue
import types


class Error:
    def __init__(self, failed=False): self.failed = failed
    def Fail(self): return self.failed


class Value:
    def __init__(self, name="x", value="42", address=4096, children=(), valid=True):
        self.name, self.value, self.address, self.children, self.valid = name, value, address, children, valid
    def GetNonSyntheticValue(self): return self
    def IsValid(self): return self.valid
    def GetError(self): return Error(not self.valid)
    def GetValue(self): return self.value
    def GetName(self): return self.name
    def GetLoadAddress(self): return self.address
    def GetNumChildren(self, *args): return len(self.children)
    def GetChildAtIndex(self, index, *args): return self.children[index]
    def GetSummary(self): raise AssertionError("Ordinary capture must not execute formatter")
    def GetData(self):
        return types.SimpleNamespace(GetByteSize=lambda: 2,
                                     ReadRawData=lambda error, offset, size: b"\x00\xff")
    def GetTypeName(self): return "aggregate"


class Values:
    def __init__(self, *values): self.values = values
    def GetSize(self): return len(self.values)
    def GetValueAtIndex(self, index): return self.values[index]


class Frame:
    def __init__(self, index=0):
        self.index = index
        self.variables = Values(Value())
        self.registers = Values(Value("general", children=(Value("rax", "0x2a"),)))
    def GetFrameID(self): return self.index
    def GetCFA(self): return 8192 + self.index * 16
    def GetFunctionName(self): return "recurse"
    def GetPC(self): return 1024 + self.index
    def GetLineEntry(self):
        return types.SimpleNamespace(IsValid=lambda: True, GetLine=lambda: 8 + self.index,
            GetFileSpec=lambda: types.SimpleNamespace(GetDirectory=lambda: "C:/program space",
                                                     GetFilename=lambda: "demo.c"))
    def GetVariables(self, *args): return self.variables
    def GetRegisters(self): return self.registers
    def EvaluateExpression(self, expr, options): return Value("$0", "43")


class Thread:
    def __init__(self, api, process):
        self.api, self.process = api, process
        self.frames = [Frame(0), Frame(1)]
        self.selected = 0
        self.reason = api.eStopReasonSignal
    def IsValid(self): return True
    def GetThreadID(self): return 17
    def GetNumFrames(self): return len(self.frames)
    def GetFrameAtIndex(self, index): return self.frames[index]
    def SetSelectedFrame(self, index): self.selected = index
    def GetStopReason(self): return self.reason
    def StepOver(self, mode): self.step("over")
    def StepInto(self, mode): self.step("into")
    def StepOut(self): self.step("out")
    def step(self, mode):
        self.process.steps.append(mode)
        self.reason = self.api.eStopReasonPlanComplete
        self.process.publish(self.api.eStateRunning)
        self.process.publish(self.api.eStateStopped)


class Process:
    def __init__(self, api):
        self.api = api
        self.state = api.eStateStopped
        self.stop_id = 1
        self.thread = Thread(api, self)
        self.listener = None
        self.steps = []
        self.detached = self.killed = self.detach_failure = self.partial = False
        self.stdout, self.stderr = [], []
    def IsValid(self): return True
    def GetProcessID(self): return 1234
    def GetState(self): return self.state
    def GetStopID(self): return self.stop_id
    def GetSelectedThread(self): return self.thread
    def SetSelectedThread(self, thread): self.thread = thread
    def GetNumThreads(self): return 1
    def GetThreadAtIndex(self, index): return self.thread
    def GetExitStatus(self): return 9
    def GetSTDOUT(self, size): return self.stdout.pop(0) if self.stdout else ""
    def GetSTDERR(self, size): return self.stderr.pop(0) if self.stderr else ""
    def SetDetachKeepsStopped(self, value): self.keep_stopped = value
    def Continue(self): self.publish(self.api.eStateRunning); return Error()
    def Stop(self):
        self.thread.reason = self.api.eStopReasonSignal
        self.publish(self.api.eStateStopped)
        return Error()
    def Kill(self): self.killed = True; self.state = self.api.eStateExited; return Error()
    def Detach(self):
        if not self.detach_failure:
            self.detached = True
            self.state = self.api.eStateDetached
        return Error(self.detach_failure)
    def ReadMemory(self, address, size, error): return b"z" * (size - int(self.partial))
    def publish(self, state):
        self.state = state
        if state == self.api.eStateStopped: self.stop_id += 1
        self.listener.queue.put(types.SimpleNamespace(process=self, state=state, stop=self.stop_id))


class Info:
    def __init__(self, value): self.value = value; self.flags = 0; self.env = []
    def GetLaunchFlags(self): return self.flags
    def SetLaunchFlags(self, flags): self.flags = flags
    def SetListener(self, listener): self.listener = listener
    def SetShellExpandArguments(self, value): self.shell = value
    def SetWorkingDirectory(self, value): self.cwd = value
    def SetEnvironmentEntries(self, value, append): self.env = value
    def AddOpenFileAction(self, *args): return True


class Target:
    def __init__(self, api): self.api = api; self.breakpoints = []
    def IsValid(self): return True
    def Launch(self, info, error):
        self.api.info = info
        self.api.process.listener = info.listener
        if self.api.launch_failure: error.failed = True
        else: self.api.process.publish(self.api.eStateStopped)
        return self.api.process
    Attach = Launch
    def BreakpointCreateByLocation(self, file, line):
        self.breakpoints.append((file, line))
        return self._bp()
    def BreakpointCreateByName(self, name): self.breakpoints.append(name); return self._bp()
    def _bp(self):
        return types.SimpleNamespace(IsValid=lambda: True, GetID=lambda: 3,
            GetNumLocations=lambda: 1, SetCondition=lambda value: setattr(self, "condition", value))


class Listener:
    def __init__(self, name): self.queue = queue.Queue()
    def WaitForEvent(self, timeout, event):
        try: source = self.queue.get(timeout=0.02)
        except queue.Empty: return False
        event.__dict__.update(source.__dict__)
        return True


def make_api():
    api = types.SimpleNamespace()
    names = ["eStateStopped", "eStateCrashed", "eStateSuspended", "eStateExited", "eStateDetached",
             "eStateRunning", "eStateStepping", "eStopReasonNone", "eStopReasonInvalid",
             "eStopReasonSignal", "eStopReasonBreakpoint", "eStopReasonWatchpoint",
             "eStopReasonPlanComplete", "eStopReasonException", "eOnlyThisThread", "eNoDynamicValues"]
    for index, name in enumerate(names): setattr(api, name, index + 1)
    api.eLaunchFlagStopAtEntry = 4
    api.eLaunchFlagLaunchInTTY = 8
    api.eLaunchFlagDisableSTDIO = 16
    api.launch_failure = False
    api.process = Process(api)
    api.target = Target(api)
    api.debugger = types.SimpleNamespace(SetAsync=lambda value: setattr(api, "asynchronous", value),
        CreateTarget=lambda path: api.target)
    api.SBDebugger = types.SimpleNamespace(Create=lambda files: (setattr(api, "init_files", files) or api.debugger),
        Destroy=lambda debugger: setattr(api, "destroyed", True))
    api.SBListener, api.SBEvent, api.SBError = Listener, types.SimpleNamespace, Error
    api.SBLaunchInfo = api.SBAttachInfo = Info
    api.SBProcess = types.SimpleNamespace(EventIsProcessEvent=lambda event: hasattr(event, "process"),
        GetProcessFromEvent=lambda event: event.process, GetStateFromEvent=lambda event: event.state,
        GetRestartedFromEvent=lambda event: False)
    api.SBExpressionOptions = lambda: types.SimpleNamespace(SetTimeoutInMicroSeconds=lambda value: None,
        SetTryAllThreads=lambda value: None, SetFetchDynamicValue=lambda value: None)
    return api
