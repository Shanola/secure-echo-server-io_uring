void do_xor(uint8_t, const uint8_t, const uint8_t, int);
int do_registration(int, uint8_t *, uint8_t *, RNG *, Sha256 *);
int do_authentication(char *, int , uint8_t *, const uint8_t *, const uint8_t *, RNG *, Sha256 *);
int config_ktls(int, const uint8_t *);
