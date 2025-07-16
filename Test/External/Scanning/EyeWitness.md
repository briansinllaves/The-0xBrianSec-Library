**`cd /home/tools/EyeWitness/Python`**: Navigate to the EyeWitness directory.

```
sudo python3 EyeWitness.py --web -x ~/scans/india/IN-web-ports.xml --timeout 10 --no-prompt -d ~/targets/india/eyewitness
```
- - **`sudo python3 EyeWitness.py`**: Run the EyeWitness script with elevated privileges.
- **`--web`**: Capture screenshots of web applications.
- **`-x ~/scans/india/IN-web-ports.xml`**: Use the `IN-web-ports.xml` file located in `~/scans/india/` as the input list of targets.
- **`--timeout 10`**: Set the timeout for each request to 10 seconds.
- **`--no-prompt`**: Run without user interaction.
- **`-d ~/targets/india/eyewitness`**: Save the output to the `~/targets/india/eyewitness` directory.