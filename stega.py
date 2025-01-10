from tkinter import Tk, Label, Button, Entry, filedialog, StringVar, messagebox, Frame
from PIL import Image
from cryptography.fernet import Fernet
import base64
import hashlib
import os


def derive_key(password):
    """Derives a symmetric key from a password."""
    password_bytes = password.encode('utf-8')
    key = hashlib.sha256(password_bytes).digest()[:32]
    return base64.urlsafe_b64encode(key)


from PIL import Image
from cryptography.fernet import Fernet
import os
from tkinter import messagebox

def derive_key(password: str) -> bytes:
    """Derive a key from the given password using a hash function."""
    return Fernet.generate_key()  # In this case, we use Fernet's method for simplicity.


# Example usage:
# encode_image_with_file('input_image.jpg', 'encoded_image', 'file_to_encode.txt', 'your_password')


def decode_image_with_password(image_path, password):
    """Decodes a password-protected file content from an image."""
    try:
        # Derive decryption key from the password
        key = derive_key(password)
        cipher = Fernet(key)

        # Open the carrier image
        image = Image.open(image_path)
        pixels = image.load()
        width, height = image.size

        binary_data = ""
        for y in range(height):
            for x in range(width):
                pixel = pixels[x, y]
                for i in range(3):  # Process RGB channels
                    binary_data += str(pixel[i] & 1)

        # Find the end of the message (EOF marker)
        binary_data = binary_data.rstrip('0')  # Remove trailing 0s

        # Convert binary data to bytes
        byte_array = bytearray()
        for i in range(0, len(binary_data), 8):
            byte_array.append(int(binary_data[i:i + 8], 2))

        encrypted_message = bytes(byte_array)
        try:
            # Decrypt the file content
            decrypted_message = cipher.decrypt(encrypted_message).decode('utf-8')
            messagebox.showinfo("Hidden File Content", decrypted_message)
        except Exception:
            messagebox.showerror("Error", "Invalid password or corrupted data.")
    except Exception as e:
        messagebox.showerror("Error", f"Error decoding the image: {e}")


def browse_image(entry):
    """Opens a file dialog to select an image."""
    file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp")])
    entry.set(file_path)


def browse_file(entry):
    """Opens a file dialog to select a text file."""
    file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    entry.set(file_path)


def encode_action():
    """Handles the encode action."""
    image_path = encode_image_path.get()
    file_path = encode_file_path.get()
    password = encode_password_entry.get()
    if not image_path or not file_path or not password:
        messagebox.showerror("Error", "All fields are required for encoding.")
        return
    output_path = filedialog.asksaveasfilename(filetypes=[("Image Files", "*.png;*.jpg;*.bmp")])
    if output_path:
        encode_image_with_file(image_path, output_path, file_path, password)


def decode_action():
    """Handles the decode action."""
    image_path = decode_image_path.get()
    password = decode_password_entry.get()
    if not image_path or not password:
        messagebox.showerror("Error", "Both image and password are required for decoding.")
        return
    decode_image_with_password(image_path, password)


# GUI Setup
root = Tk()
root.title("Image Steganography")

# Encode Section
encode_frame = Frame(root)
encode_frame.pack(pady=10)

Label(encode_frame, text="Encode Section", font=("Arial", 14)).grid(row=0, column=0, columnspan=3, pady=10)

encode_image_path = StringVar()
encode_file_path = StringVar()
encode_password_entry = StringVar()

Label(encode_frame, text="Carrier Image:").grid(row=1, column=0, padx=10, pady=5, sticky="e")
Entry(encode_frame, textvariable=encode_image_path, width=40).grid(row=1, column=1, padx=10, pady=5)
Button(encode_frame, text="Browse", command=lambda: browse_image(encode_image_path)).grid(row=1, column=2, padx=10, pady=5)

Label(encode_frame, text="Text File to Encode:").grid(row=2, column=0, padx=10, pady=5, sticky="e")
Entry(encode_frame, textvariable=encode_file_path, width=40).grid(row=2, column=1, padx=10, pady=5)
Button(encode_frame, text="Browse", command=lambda: browse_file(encode_file_path)).grid(row=2, column=2, padx=10, pady=5)

Label(encode_frame, text="Password:").grid(row=3, column=0, padx=10, pady=5, sticky="e")
Entry(encode_frame, textvariable=encode_password_entry, show="*", width=40).grid(row=3, column=1, padx=10, pady=5)

Button(encode_frame, text="Encode", command=encode_action).grid(row=4, column=0, columnspan=3, pady=10)

# Decode Section
decode_frame = Frame(root)
decode_frame.pack(pady=10)

Label(decode_frame, text="Decode Section", font=("Arial", 14)).grid(row=0, column=0, columnspan=3, pady=10)

decode_image_path = StringVar()
decode_password_entry = StringVar()

Label(decode_frame, text="Encoded Image:").grid(row=1, column=0, padx=10, pady=5, sticky="e")
Entry(decode_frame, textvariable=decode_image_path, width=40).grid(row=1, column=1, padx=10, pady=5)
Button(decode_frame, text="Browse", command=lambda: browse_image(decode_image_path)).grid(row=1, column=2, padx=10, pady=5)

Label(decode_frame, text="Password:").grid(row=2, column=0, padx=10, pady=5, sticky="e")
Entry(decode_frame, textvariable=decode_password_entry, show="*", width=40).grid(row=2, column=1, padx=10, pady=5)

Button(decode_frame, text="Decode", command=decode_action).grid(row=3, column=0, columnspan=3, pady=10)

root.mainloop()
