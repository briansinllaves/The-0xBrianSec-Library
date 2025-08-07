import os
import re

base_dir = "Malware/Weaponizing101"
full_path = os.path.join(os.getcwd(), base_dir)

for file in os.listdir(full_path):
    if file.endswith(".md"):
        md_path = os.path.join(full_path, file)
        with open(md_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Fix image paths to point to ../../assets/
        new_content = re.sub(r'!\[Slide Image\]\(([^)]+?)\)', r'![Slide Image](../../assets/\1)', content)

        with open(md_path, "w", encoding="utf-8") as f:
            f.write(new_content)

print("✅ Image paths updated.")
