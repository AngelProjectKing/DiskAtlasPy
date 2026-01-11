"""
Сборщик DiskAtlasPy в exe
"""
import os
import shutil
import subprocess
import sys

def build():
    print("Очистка старых сборок...")
    for folder in ['build', 'dist']:
        if os.path.exists(folder):
            shutil.rmtree(folder)
    
    print("Сборка exe...")
    
    cmd = [
        'pyinstaller',
        '--onefile',
        '--windowed',
        '--name', 'DiskAtlasPy',
        '--add-data', 'diskatlas;diskatlas',  
        # Для Linux/Mac: 'diskatlas:diskatlas'
        '--hidden-import', 'PySide6',
        '--hidden-import', 'cryptography',
        '--hidden-import', 'psutil',
        '--hidden-import', 'cryptography.hazmat.backends.openssl',
        '--hidden-import', 'cryptography.hazmat.primitives.ciphers',
        '--hidden-import', 'cryptography.hazmat.primitives.kdf.scrypt',
        'main.py'
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode == 0:
        print("Сборка завершена!")
        print(f"EXE файл: dist/DiskAtlasPy.exe")

        release_dir = 'release'
        os.makedirs(release_dir, exist_ok=True)

        exe_src = 'dist/DiskAtlasPy.exe'
        exe_dst = os.path.join(release_dir, 'DiskAtlasPy.exe')
        shutil.copy(exe_src, exe_dst)

        if os.path.exists('README.md'):
            shutil.copy('README.md', os.path.join(release_dir, 'README.md'))
        
        print(f"Релиз собран в папке: {release_dir}/")
    else:
        print("Ошибка сборки:")
        print(result.stderr)
        sys.exit(1)

if __name__ == '__main__':
    build()