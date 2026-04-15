#ifndef SANCHR_OPRF_H
#define SANCHR_OPRF_H

#include <stdint.h>

/**
 * Blind a phone number for OPRF evaluation.
 *
 * @param phone              Null-terminated E.164 phone string.
 * @param blinding_scalar_out  Pointer to 32 writable bytes for the blinding scalar.
 * @param blinded_point_out    Pointer to 32 writable bytes for the compressed blinded point.
 * @return 0 on success, -1 on error.
 */
int32_t sanchr_oprf_blind(const char *phone, uint8_t *blinding_scalar_out, uint8_t *blinded_point_out);

/**
 * Unblind a server OPRF response.
 *
 * @param server_response  Pointer to 32 readable bytes (compressed Ristretto point from server).
 * @param blinding_scalar  Pointer to 32 readable bytes (blinding scalar from blind step).
 * @param unblinded_out    Pointer to 32 writable bytes for the unblinded result.
 * @return 0 on success, -1 on error.
 */
int32_t sanchr_oprf_unblind(const uint8_t *server_response, const uint8_t *blinding_scalar, uint8_t *unblinded_out);

#endif
