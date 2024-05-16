

```markdown
# Family Tree Manager with SHA-256

## Description
This repository contains a Python project for managing a family tree using a SHA-256 hashing algorithm. The project includes a command-line interface (CLI) for adding and removing members, and checking ancestry relationships.

## Features
- Add and remove family members.
- Check if one member is an ancestor of another.
- Uses SHA-256 for hashing member names.

## Requirements
- Python 3.x

## Installation
No additional packages are required. Simply clone the repository and run the script.

## Usage
To use the family tree manager, run the following command:
```bash
python family_tree_cli.py
```

## Example
Here is an example of how to interact with the CLI:
```plaintext
Options:
1. Add Member
2. Delete Member
3. Check Ancestor
4. Exit

Please enter your choice: 1
Enter the name of the new member: John
Enter the name of the parent (leave blank if none): 
Member added successfully.
```

## Script Details
### Files:
- **`sha256.py`**: Implements the SHA-256 hashing algorithm.
- **`family_tree.py`**: Manages the family tree data structure.
- **`family_tree_cli.py`**: Command-line interface for interacting with the family tree.

### Functions:
- **`read_png_header(file_path)`**: Reads the header of a PNG file to extract image width, height, bit depth, and color type.
- **`write_tga_header(width, height, color_type)`**: Writes the TGA header based on the image width, height, and color type.
- **`png_to_tga(png_file_path, tga_file_path)`**: Main function that converts a PNG file to TGA format by reading the PNG data and writing it to a new TGA file.

### Example Usage
```python
# Example usage of the family tree manager
if __name__ == "__main__":
    cli = FamilyTreeCLI()
    cli.run()
```



## Contact
For any questions or suggestions, feel free to contact me at emad.k5000@gmail.com
```

