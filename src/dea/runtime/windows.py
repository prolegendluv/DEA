"""WP1: hidden native pipe/ConPTY processes and Windows Job Objects.

Create suspended, establish a kill-on-close job, then resume. Dedicated reader
and writer workers service synchronous handles; bounded thread-safe queues
bridge to asyncio. Cancel native I/O and join workers during shutdown. Do not
interpret a Ctrl-D character as a Windows input half-close.
"""

