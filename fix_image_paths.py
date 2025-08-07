import os
import re

md_folder = "Malware/Weaponizing101"
full_path = os.path.join(os.getcwd(), md_folder)

for file in os.listdir(full_path):
    if file.endswith(".md"):
        md_path = os.path.join(full_path, file)
        with open(md_path, "r", encoding="utf-8") as f:
            content = f.read()
        
        # Replace folder names with spaces to underscores in all image paths
        content = re.sub(r'\(\.\./\.\./assets/(.*?)[ ]+(.*?)\)', lambda m: f"(../../assets/{m.group(1)}_{m.group(2)})", content)

        with open(md_path, "w", encoding="utf-8") as f:
            f.write(content)

print("✅ All image links updated.")
