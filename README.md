# Shirakumo
A RPM/WPM proxy with named pipe
---

## Features

- Implement RPM/WPM in separate processes and communicate via FIFO (named pipes) to handle requests
- Allows you load it as .dll into an existing process to implement RPM/WPM proxying in another process

## KnownIssues

- Currently only works on x64 processes
- Current implementation directly calls the Win API, so that just as an example
- Processing cycle for each RPM/WPM request is long, which is not suitable for high-frequency/concurrent RPM/WPM requests.
- Current implementation is not thread-safe

## License

This project is licensed under [**TOSSRCU**](LICENSE).
```diff
+ You are free to:
	• Use: Utilize the software for any purpose not explicitly restricted
	• Copy: Reproduce the software without limitation
	• Modify: Create derivative works through remixing/transforming
	• Merge: Combine with other materials
	• Publish: Display/communicate the software publicly
	• Distribute: Share copies of the software

+ Under the following terms:
	• Attribution: Must include copyright notice and this license in all copies
	• Waifu Clause: Don't consider the author as your waifu

- You are not allowed to:
	• Sublicense: Cannot grant sublicenses for original/modified material

```
