"""Async file server with a path traversal bug (fixture, intentionally vulnerable).

The entry point awaits the read in several shapes. Some run the read in the awaiting task
(plain ``await``), others in a task of its own, whose real stack starts at the event loop.
"""

import asyncio
import os


async def read_async(path):
    """Sink: reads a file from disk inside a coroutine."""
    await asyncio.sleep(0)
    with open(path, encoding="utf-8") as fh:
        return fh.read()


class App:
    def __init__(self, base_dir):
        self.base_dir = base_dir
        self.loop = asyncio.new_event_loop()

    async def handle_request(self, how, name):
        """Entry point: read ``name`` under base_dir (unchecked) the way ``how`` says."""
        # BUG: the name is joined without checking it stays inside base_dir.
        path = os.path.join(self.base_dir, name)
        if how == "await":
            return await read_async(path)
        if how == "create_task":
            return await asyncio.create_task(read_async(path))
        if how == "gather":
            (body,) = await asyncio.gather(read_async(path))
            return body
        if how == "wait_for":
            return await asyncio.wait_for(read_async(path), timeout=5)
        if how == "task_group":
            async with asyncio.TaskGroup() as group:
                task = group.create_task(read_async(path))
            return task.result()
        if how == "nested":
            return await asyncio.create_task(self._load(path))
        raise ValueError(how)

    async def _load(self, path):
        return await asyncio.create_task(read_async(path))

    def handle_sync(self, how, name):
        """Entry point: a synchronous front that drives the app's own event loop."""
        return self.loop.run_until_complete(self.handle_request(how, name))
