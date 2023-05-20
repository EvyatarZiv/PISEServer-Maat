#!/usr/bin/env python

from pise import sym_ex_helpers_maat
import logging
import time
import maat

logger = logging.getLogger(__name__)

LIB64_PATH = ""  # TODO: Add path to lib64


class QueryRunner:
    def __init__(self, file, callsites_to_monitor):
        self.file = file
        self.engine = sym_ex_helpers_maat.PISEEngine(None, maat.ARCH.X64, maat.OS.LINUX)
        self.mode = None
        self.callsites_to_monitor = callsites_to_monitor
        self.set_membership_hooks()

    def set_membership_hooks(self) -> None:
        if self.mode == 'membership':
            return
        logger.info('Setting hooks')
        for callsite in self.callsites_to_monitor:
            callsite.set_hook(self.engine)
        self.mode = 'membership'

    def do_monitoring(self) -> bool:
        while True:
            stop_res = self.engine.run()
            if stop_res == maat.STOP.EXIT:
                if not self.engine.pop_engine_state():
                    return False  # Membership is false
                continue
            elif stop_res == maat.STOP.HOOK:
                if self.engine.idx == len(self.engine.inputs):
                    return True  # Membership is true
                else:
                    if not self.engine.pop_engine_state():
                        return False  # Membership is false
                    continue
            else:
                raise NotImplementedError

    def membership_step_by_step(self, inputs: list):
        """
        :param inputs: List of MessageTypeSymbol objects
        """
        logger.info('Performing membership, step by step')
        logger.debug('Query: %s' % inputs)
        self.set_membership_hooks()  # TODO: Will be implemented later on
        if False:
            # Cache, as of yet unimplemented
            raise NotImplementedError
        else:
            # If we haven't found anything in cache, just start from the beginning
            logger.info('No prefix exists in cache, starting from the beginning')
            # TODO: Add support for args
            self.engine.load(binary=self.file, type=maat.BIN.ELF64, args=[], libdirs=[LIB64_PATH], load_interp=True)
            self.engine.inputs = inputs
        if not self.do_monitoring():
            return False, None, 0, 0, 0  # Membership is false
        return True, None, 0, 0, 0  # TODO: Add probing


