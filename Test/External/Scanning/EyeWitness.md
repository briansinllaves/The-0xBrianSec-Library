**`cd /home/tools/EyeWitness/Python`**: Navigate to the EyeWitness directory.

```
sudo python3 EyeWitness.py --web -x ~/scans/linda/IN-web-ports.xml --timeout 10 --no-prompt -d ~/targets/linda/eyewitness
```
- - **`sudo python3 EyeWitness.py`**: Run the EyeWitness script with elevated privileges.
- **`--web`**: Capture screenshots of web applications.
- **`-x ~/scans/linda/IN-web-ports.xml`**: Use the `IN-web-ports.xml` file located in `~/scans/linda/` as the input list of targets.
- **`--timeout 10`**: Set the timeout for each request to 10 seconds.
- **`--no-prompt`**: Run without user interaction.
- **`-d ~/targets/linda/eyewitness`**: Save the output to the `~/targets/linda/eyewitness` directory.