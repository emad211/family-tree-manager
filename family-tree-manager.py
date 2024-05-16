class Sha256:
    ks = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ]

    hs = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ]

    M32 = 0xFFFFFFFF

    def __init__(self, m = None):
        self.mlen = 0
        self.buf = b''
        self.k = self.ks[:]
        self.h = self.hs[:]
        self.fin = False
        if m is not None:
            self.update(m)

    @staticmethod
    def pad(mlen):
        mdi = mlen & 0x3F
        length = (mlen << 3).to_bytes(8, 'big')
        padlen = 55 - mdi if mdi < 56 else 119 - mdi
        return b'\x80' + b'\x00' * padlen + length

    @staticmethod
    def ror(x, y):
        return ((x >> y) | (x << (32 - y))) & Sha256.M32

    @staticmethod
    def maj(x, y, z):
        return (x & y) ^ (x & z) ^ (y & z)

    @staticmethod
    def ch(x, y, z):
        return (x & y) ^ ((~x) & z)

    def compress(self, c):
        w = [0] * 64
        w[0 : 16] = [int.from_bytes(c[i : i + 4], 'big') for i in range(0, len(c), 4)]

        for i in range(16, 64):
            s0 = self.ror(w[i - 15],  7) ^ self.ror(w[i - 15], 18) ^ (w[i - 15] >>  3)
            s1 = self.ror(w[i -  2], 17) ^ self.ror(w[i -  2], 19) ^ (w[i -  2] >> 10)
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & self.M32

        a, b, c, d, e, f, g, h = self.h

        for i in range(64):
            s0 = self.ror(a, 2) ^ self.ror(a, 13) ^ self.ror(a, 22)
            t2 = s0 + self.maj(a, b, c)
            s1 = self.ror(e, 6) ^ self.ror(e, 11) ^ self.ror(e, 25)
            t1 = h + s1 + self.ch(e, f, g) + self.k[i] + w[i]

            h = g
            g = f
            f = e
            e = (d + t1) & self.M32
            d = c
            c = b
            b = a
            a = (t1 + t2) & self.M32

        for i, (x, y) in enumerate(zip(self.h, [a, b, c, d, e, f, g, h])):
            self.h[i] = (x + y) & self.M32

    def update(self, m):
        if m is None or len(m) == 0:
            return

        assert not self.fin, 'Hash already finalized and can not be updated!'

        self.mlen += len(m)
        m = self.buf + m

        for i in range(0, len(m) // 64):
            self.compress(m[64 * i : 64 * (i + 1)])

        self.buf = m[len(m) - (len(m) % 64):]

    def digest(self):
        if not self.fin:
            self.update(self.pad(self.mlen))
            self.digest = b''.join(x.to_bytes(4, 'big') for x in self.h[:8])
            self.fin = True
        return self.digest

    def hexdigest(self):
        tab = '0123456789abcdef'
        return ''.join(tab[b >> 4] + tab[b & 0xF] for b in self.digest())

def test():
    import secrets, hashlib, random
    for itest in range(500):
        data = secrets.token_bytes(random.randrange(257))
        a, b = hashlib.sha256(data).hexdigest(), Sha256(data).hexdigest()
        assert a == b, (a, b)
    for itest in range(500):
        a, b = hashlib.sha256(), Sha256()
        for j in range(random.randrange(10)):
            data = secrets.token_bytes(random.randrange(129))
            a.update(data)
            b.update(data)
        a, b = a.hexdigest(), b.hexdigest()
        assert a == b, (a, b)
    print('Sha256 tested successfully.')

if __name__ == '__main__':
    test()
class FamilyMember:
    def __init__(self, name_hash, parent_hash=None):
        self.name_hash = name_hash
        self.parent_hash = parent_hash
        self.children = []

    def __repr__(self):
        return f"FamilyMember(name_hash={self.name_hash}, parent_hash={self.parent_hash})"

class FamilyTree:
    def __init__(self):
        self.members = {}

    def add_member(self, name_hash, parent_hash=None):
        if name_hash in self.members:
            raise ValueError("Member already exists")
        member = FamilyMember(name_hash, parent_hash)
        self.members[name_hash] = member
        if parent_hash:
            self.members[parent_hash].children.append(member)

    def delete_member(self, name_hash):
        if name_hash not in self.members:
            raise ValueError("Member not found")
        member = self.members.pop(name_hash)
        if member.parent_hash:
            self.members[member.parent_hash].children.remove(member)

    def find_member(self, name_hash):
        return self.members.get(name_hash, None)

    def size(self):
        return len(self.members)

    def is_ancestor(self, ancestor_hash, descendant_hash):
        member = self.find_member(descendant_hash)
        while member and member.parent_hash is not None:
            if member.parent_hash == ancestor_hash:
                return True
            member = self.find_member(member.parent_hash)
        return False

    def are_siblings(self, hash1, hash2):
        member1 = self.find_member(hash1)
        member2 = self.find_member(hash2)
        return member1.parent_hash == member2.parent_hash if member1 and member2 else False

    def common_ancestor(self, hash1, hash2):
        ancestors_of_first = set()
        member = self.find_member(hash1)
        while member:
            ancestors_of_first.add(member.name_hash)
            member = self.find_member(member.parent_hash)
        member = self.find_member(hash2)
        while member:
            if member.name_hash in ancestors_of_first:
                return member.name_hash
            member = self.find_member(member.parent_hash)
        return None

    def furthest_descendant(self, name_hash):
        def get_max_depth(member_hash, current_depth):
            member = self.find_member(member_hash)
            if not member or not member.children:
                return current_depth
            return max(get_max_depth(child.name_hash, current_depth + 1) for child in member.children)
        return get_max_depth(name_hash, 0)

    def furthest_relationship(self):
        max_distance = 0
        furthest_members = (None, None)
        for member_hash in self.members:
            for other_member_hash in self.members:
                if member_hash != other_member_hash:
                    common_ancestor_hash = self.common_ancestor(member_hash, other_member_hash)
                    if common_ancestor_hash:
                        distance = self.furthest_descendant(common_ancestor_hash)
                        if distance > max_distance:
                            max_distance = distance
                            furthest_members = (member_hash, other_member_hash)
        return furthest_members
class FamilyTreeCLI:
    def __init__(self):
        self.family_tree = FamilyTree()

    def run(self):
        while True:
            print("\nگزینه‌ها:")
            print("1. اضافه کردن عضو")
            print("2. حذف عضو")
            print("3. بررسی جد")
            print("4. خروج")
            choice = input("لطفا گزینه خود را وارد کنید: ")

            if choice == '1':
                self.add_member()
            elif choice == '2':
                self.delete_member()
            elif choice == '3':
                self.check_ancestor()
            elif choice == '4':
                break
            else:
                print("گزینه نامعتبر است.")

    def add_member(self):
        name = input("نام عضو جدید را وارد کنید: ")
        parent_name = input("نام والدین را وارد کنید (در صورت نبود، خالی بگذارید): ")
        parent_hash = hash_name(parent_name) if parent_name else None

        if parent_hash and parent_hash not in self.family_tree.members:
            print("خطا: والدین در شجره‌نامه وجود ندارد.")
            return

        try:
            self.family_tree.add_member(hash_name(name), parent_hash)
            print("عضو با موفقیت اضافه شد.")
        except ValueError as e:
            print(e)

    def delete_member(self):
        name = input("نام عضوی که می‌خواهید حذف کنید را وارد کنید: ")
        try:
            self.family_tree.delete_member(hash_name(name))
            print("عضو با موفقیت حذف شد.")
        except ValueError as e:
            print(e)

    def check_ancestor(self):
        descendant_name = input("نام فرزند را وارد کنید: ")
        ancestor_name = input("نام جد را وارد کنید: ")
        is_ancestor = self.family_tree.is_ancestor(hash_name(ancestor_name), hash_name(descendant_name))
        print(f"آیا {ancestor_name} جد {descendant_name} است: {is_ancestor}")

if __name__ == "__main__":
    cli = FamilyTreeCLI()
    cli.run()


def hash_name(name):
    return Sha256(name.encode()).hexdigest()


