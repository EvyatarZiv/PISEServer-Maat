#!/usr/bin/env python

import sym_ex_helpers_maat
import logging
import time
import maat

logger = logging.getLogger(__name__)

LIB64_PATH = ""  # TODO: Add path to lib64


class QueryRunner:
    def __init__(self, file, callsites_to_monitor):
        self.file = file
        self.engine = maat.MaatEngine(maat.ARCH.X64, maat.OS.LINUX)
        self.mode = None
        self.callsites_to_monitor = callsites_to_monitor
        self.set_membership_hooks()
        sym_ex_helpers_maat.state_manager = maat.SimpleStateManager("./tmp")

    def set_membership_hooks(self):
        if self.mode == 'membership':
            return
        logger.info('Setting hooks')
        for callsite in self.callsites_to_monitor:
            callsite.set_hook(self.engine)
        self.mode = 'membership'

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
            sym_ex_helpers_maat.input_types = inputs
            sym_ex_helpers_maat.idx = 0
        while self.engine.run() == maat.STOP.EXIT:
            if not sym_ex_helpers_maat.pop_engine_state(self.engine):
                return False  # Membership is false
