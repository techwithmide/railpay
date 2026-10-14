package eth

import "math/bits"

var keccakRC = [24]uint64{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
	0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
	0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
	0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
	0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
}

var keccakRot = [24]int{1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44}
var keccakPi = [24]int{10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1}

func keccakF(st *[25]uint64) {
	var bc [5]uint64
	for r := 0; r < 24; r++ {
		for i := 0; i < 5; i++ {
			bc[i] = st[i] ^ st[i+5] ^ st[i+10] ^ st[i+15] ^ st[i+20]
		}
		for i := 0; i < 5; i++ {
			t := bc[(i+4)%5] ^ bits.RotateLeft64(bc[(i+1)%5], 1)
			for j := 0; j < 25; j += 5 {
				st[j+i] ^= t
			}
		}
		t := st[1]
		for i := 0; i < 24; i++ {
			j := keccakPi[i]
			bc[0] = st[j]
			st[j] = bits.RotateLeft64(t, keccakRot[i])
			t = bc[0]
		}
		for j := 0; j < 25; j += 5 {
			for i := 0; i < 5; i++ {
				bc[i] = st[j+i]
			}
			for i := 0; i < 5; i++ {
				st[j+i] ^= ^bc[(i+1)%5] & bc[(i+2)%5]
			}
		}
		st[0] ^= keccakRC[r]
	}
}

const keccakRate = 136

func Keccak256(parts ...[]byte) [32]byte {
	var st [25]uint64
	var block [keccakRate]byte
	n := 0
	absorb := func() {
		for i := 0; i < keccakRate/8; i++ {
			var w uint64
			for k := 0; k < 8; k++ {
				w |= uint64(block[i*8+k]) << (8 * k)
			}
			st[i] ^= w
		}
		keccakF(&st)
		n = 0
	}
	for _, p := range parts {
		for _, b := range p {
			block[n] = b
			n++
			if n == keccakRate {
				absorb()
			}
		}
	}
	for i := n; i < keccakRate; i++ {
		block[i] = 0
	}
	block[n] ^= 0x01
	block[keccakRate-1] ^= 0x80
	absorb()

	var out [32]byte
	for i := 0; i < 32; i++ {
		out[i] = byte(st[i/8] >> (8 * (i % 8)))
	}
	return out
}
