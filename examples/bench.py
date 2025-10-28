import sys
import os
import time
from multiprocessing import Process, Value
from dataclasses import dataclass
from inspect import cleandoc as I
from pydoc import locate

from tqdm import tqdm
import fire


@dataclass
class Stats:
    requests: int = 0
    requests_correct: int = 0
    requests_incorrect: int = 0
    requests_failure: int = 0
    mean_latency_secs: float = 0
    total_secs: float = 0
    last_failure: str = ""

    @property
    def success_rate(self) -> float:
        return (self.requests_correct * 1.0 / self.requests) if self.requests else 1.0

    def __repr__(self) -> str:
        bandwidth = self.requests / self.total_secs if self.total_secs > 0 else 0.0
        result = f"""
        - Took: {self.total_secs:.1f} CPU seconds
        - Total exchanges: {self.requests:,}
        - Success rate: {self.success_rate:.3%}
        - Mean latency: {self.mean_latency_secs * 1e6:.1f} microseconds
        - Mean bandwidth: {bandwidth:.1f} requests/s
        """
        return I(result)


def bench_serial(
    callable,
    *,
    requests_count: int = 100_000,
    seconds: float = 10,
    progress: bool = False,
) -> Stats:

    stats = Stats()
    transmits_range = range(requests_count)
    if progress:
        transmits_range = tqdm(transmits_range, leave=False)

    should_stop = False
    for _ in transmits_range:
        t1 = time.monotonic_ns()
        try:
            callable()
            stats.requests += 1
            stats.requests_correct += 1
        except AssertionError:
            stats.requests += 1
            stats.requests_incorrect += 1
        except Exception as e:
            stats.requests += 1
            stats.requests_failure += 1
            stats.last_failure = str(e)
        except KeyboardInterrupt:
            should_stop = True

        t2 = time.monotonic_ns()
        stats.total_secs += (t2 - t1) / 1.0e9
        should_stop = should_stop or stats.total_secs > seconds
        if should_stop:
            break

    stats.mean_latency_secs = stats.total_secs / (stats.requests + 1)
    return stats


def bench_parallel(
    callable,
    *,
    threads: int = 1,
    requests_count: int = 100_000,
    seconds: float = 10,
    progress: bool = False,
):

    if threads == 1:
        return bench_serial(
            callable=callable,
            seconds=seconds,
            requests_count=requests_count,
            progress=progress,
        )

    requests_correct = Value("i", 0)
    requests_incorrect = Value("i", 0)
    requests = Value("i", 0)
    mean_latency_secs = Value("f", 0)

    def run():
        stats = bench_serial(
            callable=callable,
            seconds=seconds,
            requests_count=requests_count,
            progress=False,
        )
        requests_correct.value += stats.requests_correct
        requests_incorrect.value += stats.requests_incorrect
        requests.value += stats.requests
        mean_latency_secs.value += stats.mean_latency_secs

    global_start_time = time.monotonic_ns()

    procs = []
    for _ in range(threads):
        procs.append(Process(target=run))

    [x.start() for x in procs]
    [x.join() for x in procs]

    global_end_time = time.monotonic_ns()
    total_secs = (global_end_time - global_start_time) / 1.0e9

    return Stats(
        requests_correct=requests_correct.value,
        requests_incorrect=requests_incorrect.value,
        requests=requests.value,
        mean_latency_secs=mean_latency_secs.value / threads,
        total_secs=total_secs,
    )


def main(
    class_name: str,
    *,
    threads: int = 1,
    requests: int = 100_000,
    seconds: float = 10,
    progress: bool = False,
):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.dirname(script_dir)
    sys.path.append(f"{script_dir}/login")
    sys.path.append(os.path.join(project_dir, "python"))

    class_ = locate(class_name)
    stats = bench_parallel(
        callable=class_(),
        threads=threads,
        requests_count=requests,
        seconds=seconds,
        progress=progress,
    )
    print(stats)


if __name__ == "__main__":
    fire.Fire(main)
