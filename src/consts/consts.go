package consts

const (
	BLOCK_SIZE   = 16
	KEY_SIZE     = 32
	WORD_SIZE    = 4
	NK           = 8
	NR           = 14
	NB           = 4
	ROUND_KEYS   = NR + 1
	EXP_KEY_SIZE = BLOCK_SIZE * ROUND_KEYS
	IV_SIZE      = 16
)
