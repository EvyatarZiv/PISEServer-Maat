import logging
import time
import maat


class PISEEngine(maat.MaatEngine):
    def __init__(self, inputs, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.inputs = inputs
        self.idx = 0
        self.state_manager = maat.SimpleStateManager("./tmp")

    def save_engine_state(self) -> None:
        self.state_manager.enqueue_state(self)

    def pop_engine_state(self) -> bool:
        return self.state_manager.dequeue_state(self)

    def branch_callback(self):
        cond = None
        if self.info.branch.taken:
            cond = self.info.branch.cond.invert()
        else:
            cond = self.info.branch.cond
        sl = maat.Solver()
        for cons in self.path.constraints():
            sl.add(cons)
        sl.add(cond)
        if sl.check():
            self.save_engine_state()
            self.vars.update_from(sl.get_model())
        return maat.ACTION.CONTINUE
