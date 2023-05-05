import logging
import time
import maat

global input_types
global idx
global state_manager


def save_engine_state(engine: maat.MaatEngine) -> None:
    state_manager.enqueue_state(engine)


def pop_engine_state(engine: maat.MaatEngine) -> bool:
    return state_manager.dequeue_state(engine)


def branch_callback(engine: maat.MaatEngine):
    cond = None
    if engine.info.branch.taken:
        cond = engine.info.branch.cond.invert()
    else:
        cond = engine.info.branch.cond
    sl = maat.Solver()
    for cons in engine.path.constraints():
        sl.add(cons)
    sl.add(cond)
    if sl.check():
        save_engine_state(engine)
        engine.vars.update_from(sl.get_model())
    return maat.ACTION.CONTINUE


def send_callback(engine: maat.MaatEngine) -> maat.ACTION:
    raise NotImplementedError
    return maat.ACTION.ERROR


def recv_callback(engine: maat.MaatEngine) -> maat.ACTION:
    raise NotImplementedError
    return maat.ACTION.ERROR