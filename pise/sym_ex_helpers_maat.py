import logging
import time
import maat
from copy import deepcopy

m = maat.MaatEngine(maat.ARCH.X64)


class PISEEngine(type(m)):
    def __init__(self, inputs, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.inputs = inputs
        self.idx = 0
        self.indices = []
        self.state_manager = maat.SimpleStateManager("./tmp")
        self._solvers = [maat.Solver()]
        self.solver = self._solvers[-1]

    def save_engine_state(self) -> None:
        self.state_manager.enqueue_state(self)
        sl = deepcopy(self.solver)
        self._solvers.append(sl)
        self.solver = self._solvers[-1]
        self.indices.append(self.idx)

    def pop_engine_state(self) -> bool:
        self._solvers = self._solvers[:-1]
        self.solver = self._solvers[-1]
        pop_success = self.state_manager.dequeue_state(self)
        if pop_success:
            self.idx = self.indices[-1]
            self.indices = self.indices[:-1]
        return pop_success

    def branch_callback(self):
        cond = None
        if self.info.branch.taken:
            cond = self.info.branch.cond.invert()
        else:
            cond = self.info.branch.cond
        sl = deepcopy(self.solver)
        sl.add(cond)
        if sl.check():
            self.save_engine_state()
            self.solver.add(cond)
            self.vars.update_from(self.solver.get_model())
        return maat.ACTION.CONTINUE
