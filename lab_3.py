import hashlib

def read_hashes_and_phones(filename):
    hashes_and_phones = []
    with open(filename, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                hashes_and_phones.append(line)
    return hashes_and_phones

def compute_salt(hashes_and_phones, numbers):
    phones = []
    for line in hashes_and_phones:
        parts = line.split(':')
        if len(parts) == 2:
            phones.append(parts[1])
    phone_set = set(phones)

    for phone in phone_set:
        salt = int(phone) - int(numbers[0])
        if salt < 0:
            continue

        if all(str(int(number) + salt) in phone_set for number in numbers):
            return salt

    return 0

def deobfuscate_dataset(hashes_and_phones, salt, output_file):
    with open(output_file, "w", encoding="utf-8") as f:
        for hash_phone in hashes_and_phones:
            parts = hash_phone.split(':')
            if len(parts) == 2:
                hash_value, phone = parts
                original_number = int(phone) - salt
                f.write(f"{hash_value}:{original_number}\n")

numbers = [
    "89867653009",
    "89167569880",
    "89161111524",
    "89866508295",
    "89859971245"
]

hashes_and_phones = read_hashes_and_phones("output.txt")

salt = compute_salt(hashes_and_phones, numbers)
print(f"Вычисленная соль: {salt}")

deobfuscate_dataset(hashes_and_phones, salt, "deobfuscated_output.txt")
print("Деобезличивание завершено")

def extract_phones(filename):
    phones = []
    with open(filename, "r", encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split(':')
            if len(parts) == 2:
                phones.append(parts[1])
    return phones

def hash_phones(phones, sha1_output_file, sha256_output_file, sha512_output_file):
    with open(sha1_output_file, "w", encoding="utf-8") as sha1_f, \
         open(sha256_output_file, "w", encoding="utf-8") as sha256_f, \
         open(sha512_output_file, "w", encoding="utf-8") as sha512_f:
        for phone in phones:
            sha1_hash = hashlib.sha1(phone.encode()).hexdigest()
            sha256_hash = hashlib.sha256(phone.encode()).hexdigest()
            sha512_hash = hashlib.sha512(phone.encode()).hexdigest()
            sha1_f.write(f"{sha1_hash}\n")
            sha256_f.write(f"{sha256_hash}\n")
            sha512_f.write(f"{sha512_hash}\n")

phones = extract_phones("deobfuscated_output.txt")

hash_phones(phones, "sha1_hashes.txt", "sha256_hashes.txt", "sha512_hashes.txt")
print("Хеширование завершено")