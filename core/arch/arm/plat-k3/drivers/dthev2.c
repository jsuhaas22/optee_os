// SPDX-License-Identifier: BSD-2-Clause
/*
 * Texas Instruments K3 DTHEV2 Driver
 *
 * Copyright (C) 2025 Texas Instruments Incorporated - https://www.ti.com/
 *	T Pratham <t-pratham@ti.com>
 */

#include <drivers/ti_sci.h>
#include <initcall.h>
#include <io.h>
#include <keep.h>
#include <kernel/interrupt.h>
#include <kernel/misc.h>
#include <kernel/spinlock.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <rng_support.h>

#include "eip76d_trng.h"

#define FW_ENABLE_REGION        0x0a
#define FW_BACKGROUND_REGION    BIT(8)
#define FW_BIG_ARM_PRIVID       0x04
#define FW_TIFS_PRIVID          0xca
#define FW_WILDCARD_PRIVID      0xc3
#define FW_SECURE_ONLY          GENMASK_32(7, 0)
#define FW_NON_SECURE           GENMASK_32(15, 0)

#define DTHEV2_TI_SCI_FWL_RGN_ID 0
#define DTHEV2_TI_SCI_FWL_ID 11

static TEE_Result dthev2_init(void)
{
	uint16_t fwl_id = DTHEV2_TI_SCI_FWL_ID;
	uint16_t dthev2_region = DTHEV2_TI_SCI_FWL_RGN_ID;
	uint16_t rng_region = 1; //RNG_TI_SCI_FW_RGN_ID;
	uint8_t owner_index = OPTEE_HOST_ID;
	uint8_t owner_privid = 0;
	uint16_t owner_permission_bits = 0;
	uint32_t control = 0;
	uint32_t permissions[FWL_MAX_PRIVID_SLOTS] = { };
	uint32_t num_perm = 0;
	uint64_t start_address = 0;
	uint64_t end_address = 0;
	uint32_t val = 0;
	TEE_Result result = TEE_SUCCESS;
	int ret = 0;

	DMSG("DTHEV2: Starting the FIREWALL process");

	/* Try to claim ownership of DTHEV2 Firewall */
	ret = ti_sci_change_fwl_owner(fwl_id, dthev2_region, owner_index,
				      &owner_privid, &owner_permission_bits);
	if (ret) {
		DMSG("Could not change DTHEv2 firewall owner");
	} else {
		IMSG("Fixing DTHEv2 firewall owner for GP device");

		/* Get current DTHEv2 firewall configurations */
		ret = ti_sci_get_fwl_region(fwl_id, dthev2_region, 1,
					    &control, permissions,
					    &start_address, &end_address);

		if (ret) {
			EMSG("Could not get firewall region information");
			return TEE_ERROR_GENERIC;
		}

		/* Modify SA2UL firewall to allow all others access*/
		control = FW_BACKGROUND_REGION | FW_ENABLE_REGION;
		permissions[0] = (FW_WILDCARD_PRIVID << 16) | FW_NON_SECURE;
		ret = ti_sci_set_fwl_region(fwl_id, dthev2_region, 1,
					    control, permissions,
					    0x0, UINT32_MAX);
		if (ret) {
			EMSG("Could not set firewall region information");
			return TEE_ERROR_GENERIC;
		}
	}

	/* Claim the TRNG firewall for ourselves */
	ret = ti_sci_change_fwl_owner(fwl_id, rng_region, owner_index,
				      &owner_privid, &owner_permission_bits);
	if (ret) {
		EMSG("Could not change TRNG firewall owner");
		return TEE_ERROR_GENERIC;
	}

	/* Get current TRNG firewall configuration */
	ret = ti_sci_get_fwl_region(fwl_id, rng_region, 1,
				    &control, permissions,
				    &start_address, &end_address);
	if (ret) {
		EMSG("Could not get firewall region information");
		return TEE_ERROR_GENERIC;
	}

	/* Modify TRNG firewall to block all others access */
	control = FW_ENABLE_REGION;
	start_address = RNG_BASE;
	end_address = RNG_BASE + RNG_REG_SIZE - 1;
	permissions[num_perm++] = (FW_BIG_ARM_PRIVID << 16) | FW_SECURE_ONLY;

	ret = ti_sci_set_fwl_region(fwl_id, rng_region, num_perm,
				    control, permissions,
				    start_address, end_address);
	if (ret) {
		EMSG("Could not set firewall region information");
		return TEE_ERROR_GENERIC;
	}

	IMSG("Enabled firewalls for SA2UL TRNG device");

	/* Initialize the RNG Module */
	result = eip76d_rng_init();
	if (result != TEE_SUCCESS)
		return result;

	IMSG("DTHEv2 Drivers initialized");

	return TEE_SUCCESS;
}
service_init_crypto(dthev2_init);
