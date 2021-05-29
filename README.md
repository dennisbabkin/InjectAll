# InjectAll

*Credit: I want to thank [Rbmm](https://dennisbabkin.com/blog/author/?a=rbmm) for providing [his code](https://github.com/rbmm/INJECT) as the basis for this solution.*

------------------------

This is the source code for my video tutorial that demonstrates how to code a Windows driver to inject a custom DLL into all running processes. I coded it from start to finish using C++ and x86/x64 Assembly language in Microsoft Visual Studio. The solution includes a kernel driver project, a DLL project and a C++ test console project.

For more details please [check my blog post](https://dennisbabkin.com/blog/?t=coding-windows-driver-dll-injection-into-all-running-processes-in-visual-studio).

Or watch the [entire playlist on YouTube](https://youtube.com/playlist?list=PLo7Gwt6RpLEdF1cdS7rJ3AFv_Qusbs9hD):

<div align="center">
  <a href="https://www.youtube.com/watch?v=_k3njkNkvmI"><img src="https://img.youtube.com/vi/_k3njkNkvmI/0.jpg" alt="InjectAll - Coding Windows Driver To Inject DLL Into All Processes Using Visual Studio C++ & Assembly Language | Windows | Kernel | Win32 | x86 | x64"></a>
</div>

### Build Instructions

To build this solution you will need **Microsoft Visual Studio 2019, Community Edition** with the following installed:

- **Desktop Development with C++** to build C++ projects.
- **Windows 10 SDK** to build user-mode components.
- **Windows 10 Driver Kit** to build kernel-mode driver.


--------------

Submit suggestions & bug reports [here](https://www.dennisbabkin.com/sfb/?what=bug&name=InjectAll&ver=Github).
