import hashlib
import itertools
import asyncio
import aiohttp
import string
from multiprocessing import Queue, Process, cpu_count

# Flask'tan şifreyi al
async def get_password_from_api():
    url = "http://127.0.0.1:5000/get_password"
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            if response.status == 200:
                data = await response.json()
                return data.get("password")  # Hash değeri döndürülüyor.
            else:
                print("Failed to retrieve password info from Flask API.")
                return None

# Flask'a doğru şifreyi gönder
async def post_correct_password_to_api(password):
    url = "http://127.0.0.1:5000/check_password"
    async with aiohttp.ClientSession() as session:
        async with session.post(url, json={"password": password}) as response:
            if response.status == 200:
                response_data = await response.json()
                if response_data.get("message") == "Success":
                    print(f"Password found and validated successfully: {password}")
                    return True
                else:
                    print(f"Failed to validate password on server: {password}")
            return False

# Şifreyi çözme işlemi
def crack_password(md5_hash, charset, min_length, max_length, start_letter, result_queue):
    for length in range(min_length - 1, max_length):
        for suffix in itertools.product(charset, repeat=length):
            password = start_letter + ''.join(suffix)
            if hashlib.md5(password.encode()).hexdigest() == md5_hash:
                result_queue.put(password)  # Doğru şifreyi kuyruğa koy
                return
    result_queue.put(None)  # Hiçbir şey bulunamazsa None ekle

# Ana işlem
async def main():
    md5_hash = await get_password_from_api()  # Flask'tan şifre hash'ini al
    if not md5_hash:
        print("No hash received from API. Exiting...")
        return

    charset = string.ascii_lowercase + string.digits  # Küçük harfler ve rakamlar
    min_length = 4
    max_length = 6

    # CPU çekirdek sayısına göre havuz boyutunu belirle
    pool_size = cpu_count()
    print(f"Using a pool size of: {pool_size}")

    result_queue = Queue()
    processes = []

    # Her harf için bir işlem başlat
    for start_letter in charset:
        process = Process(target=crack_password, args=(md5_hash, charset, min_length, max_length, start_letter, result_queue))
        processes.append(process)
        process.start()

    # Kuyruktan sonucu al
    cracked_password = None
    for _ in range(len(charset)):
        result = result_queue.get()  # Kuyruktan sonucu al
        if result:
            cracked_password = result
            break

    # Tüm işlemleri sonlandır
    for process in processes:
        process.terminate()

    if cracked_password:
        print(f"Cracked password: {cracked_password}")
        success = await post_correct_password_to_api(cracked_password)
        if success:
            print("Password successfully validated on server.")
        else:
            print("Validation failed.")
    else:
        print("Password could not be cracked.")

if __name__ == "__main__":
    asyncio.run(main())
