import pdb
import z3
import random
import logging

from functools import reduce
from .backend_z3 import BackendZ3

MAX_LEVEL = 6
LOGGER = logging.getLogger("claripy.backends.backend_z3_quick_sampler")
LOGGER.setLevel(logging.ERROR)


class BackendZ3QuickSampler(BackendZ3):
    def __init__(self):
        BackendZ3.__init__(self)
        self._bv_samples = None

    @staticmethod
    def _bv_count(b):
        n = b.size()
        bits = [z3.Extract(i, i, b) for i in range(n)]
        bvs = [z3.Concat(z3.BitVecVal(0, n - 1), b) for b in bits]
        nb = reduce(lambda i, j: i + j, bvs)
        return nb

    # def cast_long_to_str(x, n):
    #     # see angr/state_plugins/solver.py _cast_to
    #     return '{:x}'.format(x).zfill(n/4).decode('hex')

    def _bv_sampler(self, solver, target):

        cinr = 0
        n = target.size()
        delta = z3.BitVec('delta',  n)
        result = z3.BitVec('result', n)
        solver.add(result == target)
        solver.minimize(self._bv_count(delta))
        results = set()

        while True:
            # LOGGER.info('---------------------------')
            guess = z3.BitVecVal(random.getrandbits(n), n)
            # LOGGER.info('------------0--------------')

            solver.push()

            solver.add(result ^ delta == guess)
            LOGGER.info('------------1--------------')
            if solver.check() != z3.sat:
                LOGGER.info("**************No solution ****************")
                break

            model = solver.model()
            result0 = model[result].as_long()
            solver.pop()
            LOGGER.info('------------2--------------')
            results.add(result0)
            yield result0

            LOGGER.info('------------3--------------')
            LOGGER.info('solver: ' + str(solver))
            LOGGER.info('guess: ' + str(guess))
            LOGGER.info('model: ' + str(model))

            mutations = {}

            solver.push()
            LOGGER.info('------------4--------------')
            nresults = 0
            for i in range(n):
                LOGGER.info('mutating bit ' + str(i))
                solver.push()
                goal = z3.BitVecVal(result0, n)
                solver.add(result ^ delta == goal)
                solver.add(z3.Extract(i, i, delta) == 0x1)

                if solver.check() == z3.sat:
                    model = solver.model()
                    result1 = model[result].as_long()

                    if result1 not in results:
                        results.add(result1)
                        nresults += 1
                        yield result1

                    new_mutations = {result1: 1}

                    for value in mutations:
                        level = mutations[value]
                        if level > MAX_LEVEL:
                            continue

                        candidate = (result0 ^ ((result0 ^ value) | (result0 ^ result1)))
                        LOGGER.info('yielding candidate ' + str(candidate) + ' at level ' + str(level))

                        if candidate not in results:
                            results.add(candidate)
                            nresults += 1
                            yield candidate
                        else:
                            LOGGER.info("=============={}===========-".format(cinr))
                            cinr += 1

                        new_mutations[candidate] = level + 1

                    mutations.update(new_mutations)
                # LOGGER.info("============== Looping forever===========-")
                solver.pop()

            solver.pop()
            if not nresults:
                break

    def _batch_eval(self, exprs, n, extra_constraints=(), solver=None, model_callback=None):
        LOGGER.info("########## Quick Sampler: {}".format(n))
        # pdb.set_trace()
        if not self._bv_samples:
            LOGGER.info('set up bvsampler {}'.format(exprs))
            self._bv_samples = self._bv_sampler(z3.Optimize(), exprs[0])

        # try:
        #     return [next(self._bvsample)]
        # except StopIteration:
        #     return [None]

        # LOGGER.info('sample', sample, type(sample))
        # for r in existing_results:
        #     self.update_PST_INSTRS().add(r)

        # LOGGER.info "Batch eval existing: {}".format(self.update_PST_INSTRS())
        result_values = []
        # pdb.set_trace()
        for _ in range(n):
            # LOGGER.info('next_sample', next(sample), type(next(sample)))
            try:
                result = next(self._bv_samples)
                LOGGER.info("BVSampler next: {}".format(result))
                # while result in self.update_PST_INSTRS():
                #     result = next(self._bvsample)
                # LOGGER.info result
                result_values.append(result)
                # self.update_PST_INSTRS().add(result)
            except StopIteration:
                pdb.set_trace()
                LOGGER.info("======== Stopped Iteration ========")
                break
        # LOGGER.info(list(result_values))
        # LOGGER.info "Batch eval ends: {}".format(result_values)
        if not result_values:
            pdb.set_trace()
            return [None]
        LOGGER.info("BV Sampler: ", result_values)
        return result_values
