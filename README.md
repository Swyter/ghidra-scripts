# ghidra-scripts
Handy scripts used for cleaning up structures and reversing stuff with Ghidra SRE.

# How do I install this?
To use third-party Ghidra scripts you need to download this repository (by either `git clone` or just grabbing it as a `.zip` file) and then add the resulting folder to the script directory list where Ghidra looks them up.

1. While in your *CodeBrowser*, click on the *Script Manager* icon in the toolbar, or open it via *Window > Script Manager*:  
![imagen](https://user-images.githubusercontent.com/690187/235011713-45c3b4cd-743e-4dbd-8e4a-b5690c934363.png)

2. Click on the Manage Script Directories button in the *Script Manager* toolbar:  
![imagen](https://user-images.githubusercontent.com/690187/235011635-dd93622b-30ad-4773-aa2b-b5c1e9e45347.png)

3. Click on the *Display file chooser to add bundles to list* button, pick your folder and *Accept*:  
![imagen](https://user-images.githubusercontent.com/690187/235012478-668c56cb-ce8b-456c-a657-63df7f809fb8.png)

4. Click on the *Refresh state* button, close the *Bundle Manager*.  
![imagen](https://user-images.githubusercontent.com/690187/235013083-f8ac60dc-9353-4e7e-8dc8-7c45b53432af.png)

5. Now you can search for the imported scripts by name; and use them in various ways:
   * Toggle them on and assign them a keybind, in case you don't want the one it comes with.
   * Make sure to select the *Scripts* tree root instead of searching in a category where it may not be.
   * Scripts can also be tweaked directly with the built-in editor, if you want to make small changes.  
   * Alternatively, run them directly with the green play button, as a one-off thing.  
   
   ![imagen](https://user-images.githubusercontent.com/690187/235012919-afc4d58f-1439-437c-8165-29a01fb7d87d.png)

Hope that helps, and have fun reversing! ¯\\\_(ツ)_/¯
