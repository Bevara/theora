/*
 *			GPAC - Multimedia Framework C SDK
 *
 *			Authors: Jean Le Feuvre
 *			Copyright (c) Telecom ParisTech 2000-2022
 *					All rights reserved
 *
 *  This file is part of GPAC / image (jpg/png/bmp/j2k) reframer filter
 *
 *  GPAC is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  GPAC is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; see the file COPYING.  If not, write to
 *  the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include <gpac/filters.h>
#include <gpac/bitstream.h>
#include "jxl/decode.h"

typedef struct
{
	// options
	GF_Fraction fps;

	// only one input pid declared
	GF_FilterPid *ipid;
	// only one output pid declared
	GF_FilterPid *opid;
	u32 src_timescale;
	Bool owns_timescale;
	u32 codec_id;

	Bool initial_play_done;
	Bool is_playing;
} GF_ReframeJxlCtx;

static GF_Err rfjxl_configure_pid(GF_Filter *filter, GF_FilterPid *pid, Bool is_remove)
{
	GF_ReframeJxlCtx *ctx = gf_filter_get_udta(filter);
	const GF_PropertyValue *p;

	if (is_remove)
	{
		ctx->ipid = NULL;
		return GF_OK;
	}

	if (!gf_filter_pid_check_caps(pid))
		return GF_NOT_SUPPORTED;

	gf_filter_pid_set_framing_mode(pid, GF_TRUE);
	ctx->ipid = pid;
	// force retest of codecid
	ctx->codec_id = 0;

	p = gf_filter_pid_get_property(pid, GF_PROP_PID_TIMESCALE);
	if (p)
		ctx->src_timescale = p->value.uint;

	if (ctx->src_timescale && !ctx->opid)
	{
		ctx->opid = gf_filter_pid_new(filter);
		gf_filter_pid_copy_properties(ctx->opid, ctx->ipid);
		gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_UNFRAMED, NULL);
	}
	ctx->is_playing = GF_TRUE;
	return GF_OK;
}

static Bool rfjxl_process_event(GF_Filter *filter, const GF_FilterEvent *evt)
{
	GF_FilterEvent fevt;
	GF_ReframeJxlCtx *ctx = gf_filter_get_udta(filter);
	if (evt->base.on_pid != ctx->opid)
		return GF_TRUE;
	switch (evt->base.type)
	{
	case GF_FEVT_PLAY:
		if (ctx->is_playing)
		{
			return GF_TRUE;
		}

		ctx->is_playing = GF_TRUE;
		if (!ctx->initial_play_done)
		{
			ctx->initial_play_done = GF_TRUE;
			return GF_TRUE;
		}

		GF_FEVT_INIT(fevt, GF_FEVT_SOURCE_SEEK, ctx->ipid);
		fevt.seek.start_offset = 0;
		gf_filter_pid_send_event(ctx->ipid, &fevt);
		return GF_TRUE;
	case GF_FEVT_STOP:
		ctx->is_playing = GF_FALSE;
		return GF_FALSE;
	default:
		break;
	}
	// cancel all events
	return GF_TRUE;
}

static GF_Err rfjxl_process(GF_Filter *filter)
{
	GF_ReframeJxlCtx *ctx = gf_filter_get_udta(filter);
	GF_FilterPacket *pck, *dst_pck;
	GF_Err e;
	u8 *data, *output;
	u32 size, w = 0, h = 0, pf = 0;
	u8 *pix;
	u32 i, j, irow, in_stride, out_stride;
	GF_BitStream *bs;

	pck = gf_filter_pid_get_packet(ctx->ipid);
	if (!pck)
	{
		if (gf_filter_pid_is_eos(ctx->ipid))
		{
			if (ctx->opid)
				gf_filter_pid_set_eos(ctx->opid);
			ctx->is_playing = GF_FALSE;
			return GF_EOS;
		}
		return GF_OK;
	}
	data = (u8 *)gf_filter_pck_get_data(pck, &size);

	if (!ctx->opid || !ctx->codec_id)
	{
		const GF_PropertyValue *prop;
		u32 codecid = 0;

		JxlDecoder *decoder = JxlDecoderCreate(0);
		JxlDecoderStatus status = JxlDecoderSubscribeEvents(
			decoder, JXL_DEC_BASIC_INFO);
		if (JXL_DEC_SUCCESS != status)
		{
			GF_LOG(GF_LOG_ERROR, GF_LOG_CODEC, ("[JXL OUTPUT MESSAGE]: JxlDecoderSubscribeEvents failed\n"));
			return GF_OUT_OF_MEM;
		}

		status = JxlDecoderSetInput(decoder, data, size);
		if (JXL_DEC_SUCCESS != status)
		{
			GF_LOG(GF_LOG_ERROR, GF_LOG_CODEC, ("[JXL OUTPUT MESSAGE]: JxlDecoderSetInput failed\n"));
			return GF_NOT_SUPPORTED;
		}

		status = JxlDecoderProcessInput(decoder);
		if (JXL_DEC_BASIC_INFO != status)
		{
			JxlDecoderReleaseInput(decoder);
			GF_LOG(GF_LOG_ERROR, GF_LOG_CODEC, ("[JXL OUTPUT MESSAGE]: JxlDecoderProcessInput failed\n"));
			return GF_NON_COMPLIANT_BITSTREAM;
		}

		JxlBasicInfo info;
		status = JxlDecoderGetBasicInfo(decoder, &info);
		if (status != JXL_DEC_SUCCESS)
		{
			JxlDecoderReleaseInput(decoder);
			GF_LOG(GF_LOG_ERROR, GF_LOG_CODEC, ("[JXL OUTPUT MESSAGE]: JxlDecoderGetBasicInfo failed\n"));
			return GF_CORRUPTED_DATA;
		}

		ctx->codec_id = GF_4CC('J', 'X', 'L', ' ');
		ctx->opid = gf_filter_pid_new(filter);
		if (!ctx->opid)
		{
			gf_filter_pid_drop_packet(ctx->ipid);
			return GF_SERVICE_ERROR;
		}
		if (!ctx->fps.num || !ctx->fps.den)
		{
			ctx->fps.num = 1000;
			ctx->fps.den = 1000;
		}

		pf = (info.num_extra_channels == 1) && (info.num_color_channels == 3) ? GF_PIXEL_RGBA : (info.num_extra_channels == 1) && (info.num_color_channels == 1) ? GF_PIXEL_GREYSCALE
																							: (info.num_color_channels == 3)									 ? GF_PIXEL_RGB
																							: (info.num_color_channels == 1)									 ? GF_PIXEL_GREYSCALE
																																								 : 0;

		w = info.xsize;
		h = info.ysize;

		// we don't have input reconfig for now
		gf_filter_pid_copy_properties(ctx->opid, ctx->ipid);
		gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_STREAM_TYPE, &PROP_UINT(GF_STREAM_VISUAL));
		gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_CODECID, &PROP_UINT(ctx->codec_id));
		if (pf)
			gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_PIXFMT, &PROP_UINT(pf));
		if (w)
			gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_WIDTH, &PROP_UINT(info.xsize));
		if (h)
			gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_HEIGHT, &PROP_UINT(info.ysize));

		if (!gf_filter_pid_get_property(ctx->ipid, GF_PROP_PID_TIMESCALE))
		{
			gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_TIMESCALE, &PROP_UINT(ctx->fps.num));
			ctx->owns_timescale = GF_TRUE;
		}

		gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_NB_FRAMES, &PROP_UINT(1));
		gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_PLAYBACK_MODE, &PROP_UINT(GF_PLAYBACK_MODE_FASTFORWARD));

		JxlDecoderReleaseInput(decoder);
		JxlDecoderDestroy(decoder);
	}

	e = GF_OK;
	u32 start_offset = 0;

	dst_pck = gf_filter_pck_new_ref(ctx->opid, start_offset, size - start_offset, pck);
	if (!dst_pck)
		return GF_OUT_OF_MEM;

	gf_filter_pck_merge_properties(pck, dst_pck);
	if (ctx->owns_timescale)
	{
		gf_filter_pck_set_cts(dst_pck, 0);
		gf_filter_pck_set_sap(dst_pck, GF_FILTER_SAP_1);
		gf_filter_pck_set_duration(dst_pck, ctx->fps.den);
	}

	gf_filter_pck_send(dst_pck);
	gf_filter_pid_drop_packet(ctx->ipid);

	return e;
}

static const char *rfjxl_probe_data(const u8 *data, u32 size, GF_FilterProbeScore *score)
{
	if ((data[0] == 0xFF) && (data[1] == 0x0A))
	{
		*score = GF_FPROBE_SUPPORTED;
		return "image/jxl";
	}

	GF_BitStream *bs = gf_bs_new(data, size, GF_BITSTREAM_READ);
	u32 bsize = gf_bs_read_u32(bs);
	u32 btype = gf_bs_read_u32(bs);
	if ((bsize == 12) && (btype == GF_4CC('J', 'X', 'L', ' ')))
	{
		btype = gf_bs_read_u32(bs);
		if (btype == 0x0D0A870A)
		{
			*score = GF_FPROBE_FORCE;
			gf_bs_del(bs);
			return "image/jxl";
		}
	}
	gf_bs_del(bs);
	return NULL;
}

static const GF_FilterCapability ReframeJxlCaps[] =
	{
		CAP_UINT(GF_CAPS_INPUT, GF_PROP_PID_STREAM_TYPE, GF_STREAM_FILE),
		CAP_STRING(GF_CAPS_INPUT, GF_PROP_PID_FILE_EXT, "jxl"),
		CAP_STRING(GF_CAPS_INPUT, GF_PROP_PID_MIME, "image/jxl"),
		CAP_UINT(GF_CAPS_OUTPUT, GF_PROP_PID_STREAM_TYPE, GF_STREAM_VISUAL),
		CAP_UINT(GF_CAPS_OUTPUT, GF_PROP_PID_CODECID, GF_4CC('J', 'X', 'L', ' ')),
};

#define OFFS(_n) #_n, offsetof(GF_ReframeJxlCtx, _n)
static const GF_FilterArgs ReframeJxlArgs[] =
	{
		{OFFS(fps), "import frame rate (0 default to 1 Hz)", GF_PROP_FRACTION, "0/1000", NULL, GF_FS_ARG_HINT_HIDE},
		{0}};

GF_FilterRegister ReframeJxlRegister = {
	.name = "rfjxl",
	GF_FS_SET_DESCRIPTION("JXL reframer")
		GF_FS_SET_HELP("This filter parses JXL files/data and outputs corresponding visual PID and frames.\n")
			.private_size = sizeof(GF_ReframeJxlCtx),
	.args = ReframeJxlArgs,
	SETCAPS(ReframeJxlCaps),
	.configure_pid = rfjxl_configure_pid,
	.probe_data = rfjxl_probe_data,
	.process = rfjxl_process,
	.process_event = rfjxl_process_event};

const GF_FilterRegister * EMSCRIPTEN_KEEPALIVE dynCall_jxl_reframe_register(GF_FilterSession *session)
{
	return &ReframeJxlRegister;
}
