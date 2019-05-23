import z3
import random
import logging

from functools import reduce
from .backend_z3 import BackendZ3

MAX_LEVEL = 6
LOGGER = logging.getLogger("claripy.backends.backend_z3_quick_sampler")
LOGGER.setLevel(logging.ERROR)

CON_SOL_TIME = 0
CON_SOL_COUNT = 0
OTHER_TIME = 0
OTHER_COUNT = 0
NO_MODEL_COUNT = 0
DP_MODEL_COUNT = 0
IS_MODEL_COUNT = 0
FROM_FUZZING_TIME = 0
FROM_FUZZING_COUNT = 0
CINR = 0
HIGH_FUZZING_COUNT = 0


class BackendZ3QuickSampler(BackendZ3):
    def __init__(self):
        BackendZ3.__init__(self)
        self._bv_samples = None

    def _solver(self):
        return z3.Optimize(ctx=self._context)

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

    def log_sampler_status(self):
        LOGGER.info(
            "sigma TIME :           {}\n"
            "sigma COUNT:           {}\n"
            "sigma_level1 TIME :    {}\n"
            "sigma_level1 COUNT:    {}\n"
            "No sigma_level1 COUNT: {}\n"
            "Is sigma_level1 COUNT: {}\n"
            "DP sigma_level1 COUNT: {}\n"
            "sigma_levelN TIME :    {}\n"
            "sigma_levelN COUNT:    {}\n"
            "DP sigma_levelN COUNT: {}\n"
            "HL sigma_levelN COUNT: {}\n".format(
                CON_SOL_TIME, CON_SOL_COUNT,
                OTHER_TIME, OTHER_COUNT,
                NO_MODEL_COUNT,
                IS_MODEL_COUNT,
                DP_MODEL_COUNT,
                FROM_FUZZING_TIME,
                FROM_FUZZING_COUNT,
                CINR, HIGH_FUZZING_COUNT
            ))

    def bv_sampler(self, solver, exprs):
        global CON_SOL_TIME, CON_SOL_COUNT, OTHER_TIME, OTHER_COUNT,\
            NO_MODEL_COUNT, IS_MODEL_COUNT, DP_MODEL_COUNT, \
            FROM_FUZZING_COUNT, FROM_FUZZING_TIME, CINR, HIGH_FUZZING_COUNT
        # A collection of results (via constraint solving)
        #  and candidates (via bit flipping)
        # in the format of {value: level}
        mutations = {}
        target = exprs[0]
        assert len(exprs) == 1
        n = target.size()
        delta = z3.BitVec('delta',  n)
        result = z3.BitVec('result', n)

        # solver = self.solver()
        solver.add(result == target)
        solver.minimize(self._bv_count(delta))
        results = set()

        while True:
            # LOGGER.info('---------------------------')
            LOGGER.info("results len:", len(results))
            guess = z3.BitVecVal(random.getrandbits(min(len(results), n)) if results else 0, n)
            # LOGGER.info('------------0--------------')

            solver.push()

            solver.add(result ^ delta == guess)
            LOGGER.info('------------1--------------')
            import time
            pre = time.time()
            if solver.check() != z3.sat:
                LOGGER.info("**************No solution ****************")
                break
            model = solver.model()
            result0 = model[result].as_long()
            post = time.time()
            CON_SOL_TIME += post - pre
            CON_SOL_COUNT += 1

            solver.pop()
            LOGGER.info('------------2--------------')
            results.add(result0)

            self.log_sampler_status()
            yield result0

            LOGGER.info('------------3--------------')
            LOGGER.info('solver: ' + str(solver))
            LOGGER.info('guess: ' + str(guess))
            LOGGER.info('model: ' + str(model))
            LOGGER.info('------------4--------------')
            nresults = 0
            # From 0 to n has a low probability of finding a valid model
            # for i in range(n-1, -1, -1):
            for i in range(0, n):
                # Generating a result with the ith bit flipped
                LOGGER.info('mutating bit ' + str(i))
                solver.push()
                goal = z3.BitVecVal(result0, n)
                solver.add(result ^ delta == goal)
                solver.add(z3.Extract(i, i, delta) == 0x1)
                pre = time.time()
                if solver.check() == z3.sat:
                    model = solver.model()
                else:
                    model = None
                post = time.time()
                OTHER_TIME += post - pre
                OTHER_COUNT += 1
                self.log_sampler_status()
                solver.pop()

                # Try the next bit if the model is unsat
                if not model:
                    LOGGER.info("No model found")
                    NO_MODEL_COUNT += 1
                    self.log_sampler_status()
                    continue

                # A new result is found by the model
                new_result = model[result].as_long()

                # Try the next bit if new result is a duplicate
                if new_result in mutations:
                    LOGGER.info("Duplicated new result")
                    DP_MODEL_COUNT += 1
                    self.log_sampler_status()
                    continue

                LOGGER.info("New result found ")
                IS_MODEL_COUNT += 1
                nresults += 1
                self.log_sampler_status()
                yield new_result

                # Start combining existing mutations
                new_mutations = {new_result: 1}
                # Needs at least one result in the mutations (e.g. sigma_a)
                # to combine with the new result (e.g. sigma_b)
                # When mutations is empty, this for loop will be skipped
                for existing_result in mutations:
                    pre = time.time()
                    # print("Combining with ", existing_result)
                    level = mutations[existing_result]
                    if level > MAX_LEVEL:
                        HIGH_FUZZING_COUNT += 1
                        self.log_sampler_status()
                        continue

                    candidate = (result0 ^ ((result0 ^ existing_result) |
                                            (result0 ^ new_result)))
                    LOGGER.info('yielding candidate ' + str(candidate) + ' at level ' + str(level))

                    # Try the next existing result in mutations if
                    # this candidate is a duplicate
                    if candidate in mutations:
                        CINR += 1
                        self.log_sampler_status()
                        continue

                    # The candidate is new
                    new_mutations[candidate] = level + 1
                    nresults += 1
                    FROM_FUZZING_COUNT += 1
                    post = time.time()
                    FROM_FUZZING_TIME += (post - pre)
                    self.log_sampler_status()
                    yield candidate
                mutations.update(new_mutations)
                # LOGGER.info("============== Looping forever===========-")
            if not nresults:
                break
