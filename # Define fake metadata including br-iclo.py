import os
from PIL import Image
import piexif
import cv2
import numpy as np
from tqdm import tqdm

# Define paths
CLEAN_IMG_FOLDER = r'D:\FINAL MALWARE\New folder (4)\train - Copy\clean'
OUTPUT_FOLDER = r'D:\FINAL MALWARE\New folder (4)\metadata'

# Create output folder if it doesn't exist
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

# Define proper fake metadata including br-icloud.com.br
FAKE_METADATA = {
    "0th": {
        piexif.ImageIFD.Make: b"Apple",
        piexif.ImageIFD.Model: b"iPhone 13 Pro",
        piexif.ImageIFD.Software: b"br-icloud.com.br",
        piexif.ImageIFD.HostComputer: b"br-icloud.com.br",
    },
    "Exif": {
        piexif.ExifIFD.LensMake: b"Apple",
        piexif.ExifIFD.LensModel: b"iPhone 13 Pro back triple camera 6.1mm f/1.5",
        piexif.ExifIFD.BodySerialNumber: b"br-icloud.com.br",
    },
    "GPS": {
        piexif.GPSIFD.GPSProcessingMethod: b"ASCII\x00br-icloud.com.br\x00",  # Proper GPS format
    }
}

def validate_image_path(img_path):
    """Check if image exists and is valid"""
    if not os.path.exists(img_path):
        raise FileNotFoundError(f"Image not found: {img_path}")
    try:
        with Image.open(img_path) as img:
            img.verify()
        return True
    except Exception as e:
        print(f"Invalid image file {img_path}: {e}")
        return False

def modify_metadata(image_path, output_path):
    """Modify image metadata with proper error handling"""
    try:
        if not validate_image_path(image_path):
            return False
            
        img = Image.open(image_path)
        
        # Initialize empty EXIF if none exists
        exif_dict = {"0th": {}, "Exif": {}, "GPS": {}, "1st": {}}
        if "exif" in img.info:
            try:
                exif_dict = piexif.load(img.info["exif"])
            except Exception as e:
                print(f"Error loading EXIF from {image_path}: {e}")

        # Inject fake metadata
        for ifd in ["0th", "Exif", "GPS"]:
            if ifd not in exif_dict:
                exif_dict[ifd] = {}
            exif_dict[ifd].update(FAKE_METADATA.get(ifd, {}))
        
        # Convert to bytes and save
        exif_bytes = piexif.dump(exif_dict)
        img.save(output_path, exif=exif_bytes, quality=95)
        return True
        
    except Exception as e:
        print(f"Metadata error for {image_path}: {e}")
        return False

def chi_square_evasion(image_path, output_path):
    """Apply chi-square evasion with proper error handling"""
    try:
        img = cv2.imread(image_path, cv2.IMREAD_UNCHANGED)
        if img is None:
            raise ValueError(f"Could not read image {image_path}")
            
        # Apply minor pixel variations
        noise = np.random.randint(-2, 3, img.shape, dtype=np.int8)
        img_noisy = np.clip(img.astype(np.int16) + noise, 0, 255).astype(np.uint8)
        
        # Save with same quality as original
        cv2.imwrite(output_path, img_noisy, [cv2.IMWRITE_JPEG_QUALITY, 95])
        return True
        
    except Exception as e:
        print(f"Chi-square evasion error for {image_path}: {e}")
        return False

# Get images (2000-4000)
clean_images = sorted([
    f for f in os.listdir(CLEAN_IMG_FOLDER) 
    if f.lower().endswith(('.png', '.jpg', '.jpeg'))
])[2000:4000]

# Process images
success_count = 0
for img_name in tqdm(clean_images, desc="Processing Images"):
    img_path = os.path.join(CLEAN_IMG_FOLDER, img_name)
    output_path = os.path.join(OUTPUT_FOLDER, img_name)
    
    # Create temp file to avoid corruption
    temp_path = output_path + '.tmp'
    
    try:
        # Step 1: Modify Metadata
        if modify_metadata(img_path, temp_path):
            # Step 2: Apply Chi-Square Evasion
            if chi_square_evasion(temp_path, output_path):
                success_count += 1
    finally:
        # Clean up temp file if it exists
        if os.path.exists(temp_path):
            os.remove(temp_path)

print(f"✅ Processing completed: {success_count}/{len(clean_images)} images successfully processed")
print(f"Saved to: {OUTPUT_FOLDER}")