import angr
import contextlib

@contextlib.contextmanager
def hook0(project):
    try:
        project.hook(0x0, angr.SIM_PROCEDURES['stubs']['PathTerminator'](project=project))
        yield
    finally:
        project.unhook(0x0)

