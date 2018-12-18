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

    @staticmethod
    def update_pst_strs():
        global PST_INSTRS
        return PST_INSTRS

    def _bv_sampler(self, solver, target):
        global PST_INSTRS

        cinr = 0
        n = target.size()
        delta = z3.BitVec('delta',  n)
        result = z3.BitVec('result', n)
        solver.add(result == target)
        solver.minimize(self._bv_count(delta))
        results = set()

        while True:
            # print('---------------------------')
            guess = z3.BitVecVal(random.getrandbits(n), n)
            # print('------------0--------------')

            solver.push()

            solver.add(result ^ delta == guess)
            print('------------1--------------')
            if solver.check() != z3.sat:
                print("**************No solution ****************")
                break

            model = solver.model()
            result0 = model[result].as_long()
            solver.pop()
            print('------------2--------------')
            results.add(result0)
            yield result0

            print('------------3--------------')
            print('solver: ' + str(solver))
            print('guess: ' + str(guess))
            print('model: ' + str(model))

            mutations = {}

            solver.push()
            print('------------4--------------')
            nresults = 0
            for i in range(n):
                print('mutating bit ' + str(i))
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
                        print('yielding candidate ' + str(candidate) + ' at level ' + str(level))

                        if candidate not in results:
                            results.add(candidate)
                            nresults += 1
                            yield candidate
                        else:
                            print("=============={}===========-".format(cinr))
                            cinr += 1

                        new_mutations[candidate] = level + 1

                    mutations.update(new_mutations)
                # print("============== Looping forever===========-")
                solver.pop()

            solver.pop()
            if not nresults:
                break

    def _batch_eval(self, exprs, n, extra_constraints=(), solver=None, model_callback=None):
        global PST_INSTRS
        print("##### In BVSampler #####")
        if not self._bv_samples:
            print('set up bvsampler {}'.format(exprs))
            self._bv_samples = self._bv_sampler(solver, exprs[0])

        # try:
        #     return [next(self._bvsample)]
        # except StopIteration:
        #     return [None]

        # print('sample', sample, type(sample))
        # for r in existing_results:
        #     self.update_PST_INSTRS().add(r)

        # print "Batch eval existing: {}".format(self.update_PST_INSTRS())
        result_values = []
        pdb.set_trace()
        for _ in range(n):
            # print('next_sample', next(sample), type(next(sample)))
            try:
                result = next(self._bv_samples)
                print("BVSampler next: {}".format(result))
                # while result in self.update_PST_INSTRS():
                #     result = next(self._bvsample)
                # print result
                result_values.append(result)
                # self.update_PST_INSTRS().add(result)
            except StopIteration:
                pdb.set_trace()
                print("======== Stopped Iteration ========")
                break
        # print(list(result_values))
        # print "Batch eval ends: {}".format(result_values)
        if not result_values:
            pdb.set_trace()
            return [None]
        return result_values
