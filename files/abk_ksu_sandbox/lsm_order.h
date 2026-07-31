/* SPDX-License-Identifier: GPL-3.0-only */
/* ABK_KSU_SANDBOX_V1 */
#ifndef __KSU_ABK_SANDBOX_LSM_ORDER_H
#define __KSU_ABK_SANDBOX_LSM_ORDER_H

static inline bool abk_lsm_token_equals(const char *token, size_t length,
					const char *name)
{
	size_t index;

	for (index = 0; index < length; index++) {
		if (!name[index] || token[index] != name[index])
			return false;
	}
	return name[length] == '\0';
}

static inline bool abk_lsm_tokens_equal(const char *left, size_t left_length,
					const char *right, size_t right_length)
{
	size_t index;

	if (left_length != right_length)
		return false;
	for (index = 0; index < left_length; index++) {
		if (left[index] != right[index])
			return false;
	}
	return true;
}

static inline bool abk_lsm_order_is_safe(const char *list,
					 bool allow_ksu_tail)
{
	const char *cursor;
	const char *end;
	bool previous_is_sandbox = false;
	bool last_is_sandbox = false;
	bool last_is_ksu = false;
	unsigned int sandbox_count = 0;
	unsigned int ksu_count = 0;

	if (!list || !*list)
		return false;

	cursor = list;
	for (;;) {
		const char *prior;
		size_t length;

		end = cursor;
		while (*end && *end != ',')
			end++;
		length = end - cursor;
		if (!length)
			return false;
		prior = list;
		while (prior < cursor) {
			const char *prior_end = prior;
			size_t prior_length;

			while (*prior_end && *prior_end != ',')
				prior_end++;
			prior_length = prior_end - prior;
			if (abk_lsm_tokens_equal(prior, prior_length,
						 cursor, length))
				return false;
			prior = prior_end + 1;
		}

		previous_is_sandbox = last_is_sandbox;
		last_is_sandbox = abk_lsm_token_equals(
			cursor, length, "abk_ksu_sandbox");
		last_is_ksu = abk_lsm_token_equals(cursor, length, "ksu");
		if (last_is_sandbox)
			sandbox_count++;
		if (last_is_ksu)
			ksu_count++;

		if (!*end)
			break;
		cursor = end + 1;
	}

	if (sandbox_count != 1 || ksu_count > 1)
		return false;
	return last_is_sandbox ||
		(allow_ksu_tail && last_is_ksu && previous_is_sandbox &&
		 ksu_count == 1);
}

#endif /* __KSU_ABK_SANDBOX_LSM_ORDER_H */
