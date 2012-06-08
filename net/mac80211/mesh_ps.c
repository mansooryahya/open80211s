/*
 * Copyright 2012, Marco Porsch <marco.porsch@s2005.tu-chemnitz.de>
 * Copyright 2012, cozybit Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "mesh.h"
#include "wme.h"
#include <linux/export.h>

/* time to wakeup before and stay awake after peer TBTT until beacon receipt
 * needed to cope with stack delay and HW wakeup time
 */
#define MPS_TBTT_MARGIN	20000	/* in us units */


static inline bool test_and_set_mpsp_flag(struct sta_info *sta,
					  enum ieee80211_sta_info_flags flag)
{
	if (!test_and_set_sta_flag(sta, flag)) {
		atomic_inc(&sta->sdata->u.mesh.num_mpsp);
		return false;
	}
	return true;
}

static inline bool test_and_clear_mpsp_flag(struct sta_info *sta,
					    enum ieee80211_sta_info_flags flag)
{
	if (test_and_clear_sta_flag(sta, flag)) {
		atomic_dec(&sta->sdata->u.mesh.num_mpsp);
		return true;
	}
	return false;
}


/* mesh PS management */

/**
 * mps_null_get - create pre-addressed QoS Null frame for mesh powersave
 *
 * Returns the created sk_buff
 *
 * @sta: mesh STA
 */
static struct sk_buff *mps_qos_null_get(struct sta_info *sta)
{
	struct ieee80211_sub_if_data *sdata = sta->sdata;
	struct ieee80211_local *local = sdata->local;
	struct ieee80211_hdr *nullfunc; /* use 4addr header */
	struct sk_buff *skb;
	int size = sizeof(*nullfunc);
	__le16 fc;

	skb = dev_alloc_skb(local->hw.extra_tx_headroom + size + 2);
	if (!skb)
		return NULL;
	skb_reserve(skb, local->hw.extra_tx_headroom);

	nullfunc = (struct ieee80211_hdr *) skb_put(skb, size);
	fc = cpu_to_le16(IEEE80211_FTYPE_DATA | IEEE80211_STYPE_QOS_NULLFUNC);
	ieee80211_fill_mesh_addresses(nullfunc, &fc, sta->sta.addr,
				      sdata->vif.addr);
	nullfunc->frame_control = fc;
	nullfunc->duration_id = 0;
	/* no address resolution for this frame -> set addr 1 immediately */
	memcpy(nullfunc->addr1, sta->sta.addr, ETH_ALEN);
	skb_put(skb, 2); /* append QoS control field */
	ieee80211_mps_set_frame_flags(sdata, sta, nullfunc);

	return skb;
}

/**
 * mps_null_tx - send a QoS Null to peer to indicate link-specific power mode
 *
 * @sta: mesh STA to inform
 */
static void mps_qos_null_tx(struct sta_info *sta)
{
	struct sk_buff *skb;

	skb = mps_qos_null_get(sta);
	if (!skb)
		return;

	mps_dbg(sta->sdata, "announcing peer-specific power mode to %pM\n",
		sta->sta.addr);

	/* don't unintentionally start a MPSP */
	if (!test_sta_flag(sta, WLAN_STA_PS_STA)) {
		__le16 *qc = (__le16 *) ieee80211_get_qos_ctl(
				(struct ieee80211_hdr *) skb->data);

		*qc |= cpu_to_le16(IEEE80211_QOS_CTL_EOSP);
	}

	ieee80211_tx_skb(sta->sdata, skb);
}

/**
 * ieee80211_mps_local_status_update - track status of local link-specific PMs
 *
 * @sdata: local mesh subif
 *
 * sets the non-peer power mode and triggers the driver PS (re-)configuration
 * called by cfg80211, on peer link changes and by a timer for delayed setting
 */
void ieee80211_mps_local_status_update(struct ieee80211_sub_if_data *sdata)
{
	struct ieee80211_if_mesh *ifmsh = &sdata->u.mesh;
	struct sta_info *sta;
	bool peering = false, authenticating = false;
	int light_sleep_cnt = 0;
	int deep_sleep_cnt = 0;

	rcu_read_lock();
	list_for_each_entry_rcu(sta, &sdata->local->sta_list, list) {
		if (sdata != sta->sdata)
			continue;

		switch (sta->plink_state) {
		case NL80211_PLINK_OPN_SNT:
		case NL80211_PLINK_OPN_RCVD:
		case NL80211_PLINK_CNF_RCVD:
			peering = true;
			break;
		case NL80211_PLINK_ESTAB:
			if (sta->local_pm == NL80211_MESH_POWER_LIGHT_SLEEP)
				light_sleep_cnt++;
			else if (sta->local_pm == NL80211_MESH_POWER_DEEP_SLEEP)
				deep_sleep_cnt++;
			break;
		default:
			break;
		}

		if (!test_sta_flag(sta, WLAN_STA_AUTH) ||
		    !test_sta_flag(sta, WLAN_STA_AUTHORIZED))
			authenticating = true;
	}
	rcu_read_unlock();

	/* set non-peer mode to active during peering/scanning/authentication
	 * (see IEEE802.11-2012 13.14.8.3)
	 * the non-peer mesh power mode is deep sleep if the local STA is in
	 * light or deep sleep towards at least one mesh peer (see 13.14.3.1)
	 * otherwise set it to the user-configured default value
	 */
	if (peering || authenticating) {
		mps_dbg(sdata, "set non-peer PM to active during peer/auth\n");
		ifmsh->nonpeer_pm = NL80211_MESH_POWER_ACTIVE;
	} else if (light_sleep_cnt || deep_sleep_cnt) {
		mps_dbg(sdata, "set non-peer PM to deep sleep\n");
		ifmsh->nonpeer_pm = NL80211_MESH_POWER_DEEP_SLEEP;
	} else {
		mps_dbg(sdata, "set non-peer PM to user value\n");
		ifmsh->nonpeer_pm = ifmsh->mshcfg.power_mode;
	}

	ifmsh->ps_peers_light_sleep = light_sleep_cnt;
	ifmsh->ps_peers_deep_sleep = deep_sleep_cnt;

	set_bit(MESH_WORK_PS_HW_CONF, &sdata->u.mesh.wrkq_flags);
	ieee80211_queue_work(&sdata->local->hw, &sdata->work);
}

/**
 * ieee80211_mps_set_sta_local_pm - set local PM towards a mesh STA
 *
 * @sta: mesh STA
 * @pm: the power mode to set
 * @delay: delay in msecs for committing and announcing the new value
 *
 * called by cfg80211 and on peer link establishment
 */
void ieee80211_mps_set_sta_local_pm(struct sta_info *sta,
				    enum nl80211_mesh_power_mode pm,
				    u32 delay)
{
	struct ieee80211_sub_if_data *sdata = sta->sdata;
	static const char *modes[] = {
			[NL80211_MESH_POWER_ACTIVE] = "active",
			[NL80211_MESH_POWER_LIGHT_SLEEP] = "light sleep",
			[NL80211_MESH_POWER_DEEP_SLEEP] = "deep sleep",
	};

	if (delay) {
		/* after peering/authentication/scanning it is useful to delay
		 * the transition to a lower power mode to avoid frame losses
		 * also intended for per-link dynamic powersave
		 */
		sta->local_pm_delayed = pm;
		mod_timer(&sta->local_pm_timer,
			  jiffies + msecs_to_jiffies(delay));
		return;
	}

	mps_dbg(sdata, "local STA operates in %s mode with %pM\n",
		modes[pm], sta->sta.addr);

	sta->local_pm = pm;

	/* announce peer-specific power mode transition
	 * see IEEE802.11-2012 13.14.3.2 and 13.14.3.3
	 */
	if (sta->plink_state == NL80211_PLINK_ESTAB)
		mps_qos_null_tx(sta);

	/* only sleep once all beacons are received */
	if (pm != NL80211_MESH_POWER_ACTIVE)
		set_sta_flag(sta, WLAN_STA_MPS_WAIT_FOR_BEACON);

	ieee80211_mps_local_status_update(sdata);
}

void ieee80211_mps_sta_local_pm_timer(unsigned long data)
{
	/* This STA is valid because free_sta_work() will
	 * del_timer_sync() this timer after having made sure
	 * it cannot be armed (by deleting the plink.)
	 */
	struct sta_info *sta = (struct sta_info *) data;

	ieee80211_mps_set_sta_local_pm(sta, sta->local_pm_delayed, 0);
}

/**
 * ieee80211_mps_set_frame_flags - set mesh PS flags in FC (and QoS Control)
 *
 * @sdata: local mesh subif
 * @sta: mesh STA
 * @hdr: 802.11 frame header
 *
 * see IEEE802.11-2012 8.2.4.1.7 and 8.2.4.5.11
 *
 * NOTE: sta must be given when an individually-addressed QoS frame header
 * is handled, for group-addressed and management frames it is not used
 */
void ieee80211_mps_set_frame_flags(struct ieee80211_sub_if_data *sdata,
				   struct sta_info *sta,
				   struct ieee80211_hdr *hdr)
{
	enum nl80211_mesh_power_mode pm;
	__le16 *qc;

	if (WARN_ON(is_unicast_ether_addr(hdr->addr1) &&
		    ieee80211_is_data_qos(hdr->frame_control) &&
		    !sta))
		return;

	WARN_ON(is_zero_ether_addr(hdr->addr1)); /* consider using is_valid_ether_addr */

	if (is_unicast_ether_addr(hdr->addr1) &&
	    ieee80211_is_data_qos(hdr->frame_control) &&
	    sta->plink_state == NL80211_PLINK_ESTAB)
		pm = sta->local_pm;
	else
		pm = sdata->u.mesh.nonpeer_pm;

	if (pm == NL80211_MESH_POWER_ACTIVE)
		hdr->frame_control &= cpu_to_le16(~IEEE80211_FCTL_PM);
	else
		hdr->frame_control |= cpu_to_le16(IEEE80211_FCTL_PM);

	if (!ieee80211_is_data_qos(hdr->frame_control))
		return;

	qc = (__le16 *) ieee80211_get_qos_ctl(hdr);

	if ((is_unicast_ether_addr(hdr->addr1) &&
	     pm == NL80211_MESH_POWER_DEEP_SLEEP) ||
	    (is_multicast_ether_addr(hdr->addr1) &&
	     sdata->u.mesh.ps_peers_deep_sleep > 0))
		*qc |= cpu_to_le16(IEEE80211_QOS_CTL_MESH_PS_LEVEL);
	else
		*qc &= cpu_to_le16(~IEEE80211_QOS_CTL_MESH_PS_LEVEL);
}

/**
 * ieee80211_mps_sta_status_update - update buffering status of neighbor STA
 *
 * @sta: mesh STA
 *
 * called after change of peering status or non-peer/peer-specific power mode
 */
void ieee80211_mps_sta_status_update(struct sta_info *sta)
{
	enum nl80211_mesh_power_mode pm;
	bool do_buffer;

	/* use peer-specific power mode if peering is established and
	 * the peer's power mode is known
	 */
	if (sta->plink_state == NL80211_PLINK_ESTAB &&
	    sta->peer_pm != NL80211_MESH_POWER_UNKNOWN)
		pm = sta->peer_pm;
	else
		pm = sta->nonpeer_pm;

	do_buffer = (pm != NL80211_MESH_POWER_ACTIVE);

	/* Don't let the same PS state be set twice */
	if (test_sta_flag(sta, WLAN_STA_PS_STA) == do_buffer)
		return;

	if (do_buffer) {
		set_sta_flag(sta, WLAN_STA_PS_STA);
		atomic_inc(&sta->sdata->u.mesh.ps.num_sta_ps);
		mps_dbg(sta->sdata, "start PS buffering frames towards %pM\n",
			sta->sta.addr);
	} else {
		ieee80211_sta_ps_deliver_wakeup(sta);
	}

	/* clear the MPSP flags for non-peers or active STA */
	if (sta->plink_state != NL80211_PLINK_ESTAB) {
		test_and_clear_mpsp_flag(sta, WLAN_STA_MPSP_OWNER);
		test_and_clear_mpsp_flag(sta, WLAN_STA_MPSP_RECIPIENT);
	} else if (!do_buffer) {
		test_and_clear_mpsp_flag(sta, WLAN_STA_MPSP_OWNER);
	}

	mps_dbg(sta->sdata, "num_sta_ps is %d\n", atomic_read(&sta->sdata->u.mesh.ps.num_sta_ps));
}

static void mps_set_sta_peer_pm(struct sta_info *sta,
				struct ieee80211_hdr *hdr)
{
	enum nl80211_mesh_power_mode pm;
	__le16 *qc = (__le16 *) ieee80211_get_qos_ctl(hdr);
	static const char *modes[] = {
		[NL80211_MESH_POWER_ACTIVE] = "active",
		[NL80211_MESH_POWER_LIGHT_SLEEP] = "light sleep",
		[NL80211_MESH_POWER_DEEP_SLEEP] = "deep sleep",
	};

	/* Test Power Managment field of frame control (PW) and
	 * mesh power save level subfield of QoS control field (PSL)
	 *
	 * | PM | PSL| Mesh PM |
	 * +----+----+---------+
	 * | 0  |Rsrv|  Active |
	 * | 1  | 0  |  Light  |
	 * | 1  | 1  |  Deep   |
	 */
	if (ieee80211_has_pm(hdr->frame_control)) {
		if (ieee80211_has_qos_mesh_ps(*qc))
			pm = NL80211_MESH_POWER_DEEP_SLEEP;
		else
			pm = NL80211_MESH_POWER_LIGHT_SLEEP;
	} else {
		pm = NL80211_MESH_POWER_ACTIVE;
	}

	if (sta->peer_pm == pm)
		return;

	mps_dbg(sta->sdata, "STA %pM enters %s mode\n",
		sta->sta.addr, modes[pm]);

	sta->peer_pm = pm;

	ieee80211_mps_sta_status_update(sta);
}

static void mps_set_sta_nonpeer_pm(struct sta_info *sta,
				   struct ieee80211_hdr *hdr)
{
	enum nl80211_mesh_power_mode pm;
	static const char *modes[] = {
		[NL80211_MESH_POWER_ACTIVE] = "active",
		[NL80211_MESH_POWER_DEEP_SLEEP] = "deep sleep",
	};

	if (ieee80211_has_pm(hdr->frame_control))
		pm = NL80211_MESH_POWER_DEEP_SLEEP;
	else
		pm = NL80211_MESH_POWER_ACTIVE;

	if (sta->nonpeer_pm == pm)
		return;

	mps_dbg(sta->sdata, "STA %pM sets non-peer mode to %s\n",
		sta->sta.addr, modes[pm]);

	sta->nonpeer_pm = pm;

	ieee80211_mps_sta_status_update(sta);
}

/**
 * ieee80211_mps_rx_h_sta_process - frame receive handler for mesh powersave
 *
 * @sta: STA info that transmitted the frame
 * @hdr: IEEE 802.11 (QoS) Header
 */
void ieee80211_mps_rx_h_sta_process(struct sta_info *sta,
				    struct ieee80211_hdr *hdr)
{
	if (is_unicast_ether_addr(hdr->addr1) &&
	    ieee80211_is_data_qos(hdr->frame_control)) {
		/* individually addressed QoS Data/Null frames contain
		 * peer link-specific PS mode towards the local STA
		 */
		mps_set_sta_peer_pm(sta, hdr);

		/* check for mesh Peer Service Period trigger frames */
		ieee80211_mpsp_trigger_process(hdr, sta, false, false);
	} else {
		/* can only determine non-peer PS mode
		 * (see IEEE802.11-2012 8.2.4.1.7)
		 */
		mps_set_sta_nonpeer_pm(sta, hdr);
	}
}


/* mesh PS frame release */

static void mpsp_trigger_send(struct sta_info *sta,
			      bool rspi, bool eosp)
{
	struct ieee80211_sub_if_data *sdata = sta->sdata;
	struct sk_buff *skb;
	struct ieee80211_hdr *nullfunc;
	struct ieee80211_tx_info *info;
	__le16 *qc;

	skb = mps_qos_null_get(sta);
	if (!skb)
		return;

	nullfunc = (struct ieee80211_hdr *) skb->data;
	if (!eosp)
		nullfunc->frame_control |=
				cpu_to_le16(IEEE80211_FCTL_MOREDATA);
	/* | RSPI | EOSP |  MPSP triggering   |
	 * +------+------+--------------------+
	 * |  0   |  0   | local STA is owner |
	 * |  0   |  1   | no MPSP (MPSP end) |
	 * |  1   |  0   | both STA are owner |
	 * |  1   |  1   | peer STA is owner  | see IEEE802.11-2012 13.14.9.2
	 */
	qc = (__le16 *) ieee80211_get_qos_ctl(nullfunc);
	if (rspi)
		*qc |= cpu_to_le16(IEEE80211_QOS_CTL_RSPI);
	if (eosp)
		*qc |= cpu_to_le16(IEEE80211_QOS_CTL_EOSP);

	info = IEEE80211_SKB_CB(skb);

	info->flags |= IEEE80211_TX_CTL_NO_PS_BUFFER |
		       IEEE80211_TX_CTL_REQ_TX_STATUS;

	mps_dbg(sdata, "sending MPSP trigger%s%s to %pM\n",
		rspi ? " RSPI" : "", eosp ? " EOSP" : "", sta->sta.addr);

	ieee80211_tx_skb(sdata, skb);
}

/**
 * mpsp_qos_null_append - append QoS Null frame to MPSP skb queue if needed
 *
 * @sta: peer mesh STA we are sending frames to
 * @frames: skb queue to append to
 *
 * To properly end a mesh MPSP the last transmitted frame has to set the EOSP
 * flag in the QoS Control field. In case the current tailing frame is not a
 * QoS Data frame, append a QoS Null to carry the flag.
 */
static void mpsp_qos_null_append(struct sta_info *sta,
				 struct sk_buff_head *frames)
{
	struct ieee80211_sub_if_data *sdata = sta->sdata;
	struct sk_buff *new_skb, *skb = skb_peek_tail(frames);
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *) skb->data;
	struct ieee80211_tx_info *info;

	if (ieee80211_is_data_qos(hdr->frame_control))
		return;

	new_skb = mps_qos_null_get(sta);
	if (!new_skb)
		return;

	mps_dbg(sdata, "appending QoS Null in MPSP towards %pM\n",
		sta->sta.addr);

	/* should be transmitted last -> lowest priority */
	new_skb->priority = 1;
	skb_set_queue_mapping(new_skb, IEEE80211_AC_BK);
	ieee80211_set_qos_hdr(sdata, new_skb);

	info = IEEE80211_SKB_CB(new_skb);
	info->control.vif = &sdata->vif;
	info->flags |= IEEE80211_TX_INTFL_NEED_TXPROCESSING;

	skb_queue_tail(frames, new_skb);
}

/**
 * mps_frame_deliver - transmit frames during mesh powersave
 *
 * @sta: STA info to transmit to
 * @n_frames: number of frames to transmit. -1 for all
 */
static void mps_frame_deliver(struct sta_info *sta, int n_frames)
{
	struct ieee80211_sub_if_data *sdata = sta->sdata;
	struct ieee80211_local *local = sdata->local;
	int ac;
	struct sk_buff_head frames;
	struct sk_buff *skb;
	bool more_data = false;

	skb_queue_head_init(&frames);

	/* collect frame(s) from buffers */
	for (ac = 0; ac < IEEE80211_NUM_ACS; ac++) {
		struct sk_buff *skb;

		while (n_frames != 0) {
			skb = skb_dequeue(&sta->tx_filtered[ac]);
			if (!skb) {
				skb = skb_dequeue(
					&sta->ps_tx_buf[ac]);
				if (skb)
					local->total_ps_buffered--;
			}
			if (!skb)
				break;
			n_frames--;
			skb_queue_tail(&frames, skb);
		}

		if (!skb_queue_empty(&sta->tx_filtered[ac]) ||
		    !skb_queue_empty(&sta->ps_tx_buf[ac])) {
			more_data = true;
		}
	}

	/* nothing to send? -> EOSP */
	if (skb_queue_empty(&frames)) {
		mpsp_trigger_send(sta, false, true);
		return;
	}

	/* in a MPSP make sure the last skb is a QoS Data frame */
	if (test_sta_flag(sta, WLAN_STA_MPSP_OWNER))
		mpsp_qos_null_append(sta, &frames);

	mps_dbg(sta->sdata, "sending %d frames to PS STA %pM\n",
		skb_queue_len(&frames), sta->sta.addr);

	/* prepare collected frames for transmission */
	skb_queue_walk(&frames, skb) {
		struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
		struct ieee80211_hdr *hdr = (void *) skb->data;

		/* Tell TX path to send this frame even though the
		 * STA may still remain is PS mode after this frame
		 * exchange.
		 */
		info->flags |= IEEE80211_TX_CTL_NO_PS_BUFFER;

		if (more_data || !skb_queue_is_last(&frames, skb))
			hdr->frame_control |=
				cpu_to_le16(IEEE80211_FCTL_MOREDATA);
		else
			hdr->frame_control &=
				cpu_to_le16(~IEEE80211_FCTL_MOREDATA);

		if (skb_queue_is_last(&frames, skb) &&
		    ieee80211_is_data_qos(hdr->frame_control)) {
			u8 *qoshdr = ieee80211_get_qos_ctl(hdr);

			/* MPSP trigger frame ends service period */
			*qoshdr |= IEEE80211_QOS_CTL_EOSP;
			info->flags |= IEEE80211_TX_CTL_REQ_TX_STATUS;
		}
	}

	ieee80211_add_pending_skbs(local, &frames);
	sta_info_recalc_tim(sta);
}

/**
 * ieee80211_mpsp_trigger_process - track status of mesh Peer Service Periods
 *
 * @hdr: IEEE 802.11 QoS Header
 * @sta: peer to start a MPSP with
 * @tx: frame was transmitted by the local STA
 * @acked: frame has been transmitted successfully
 *
 * NOTE: active mode STA may only serve as MPSP owner
 */
void ieee80211_mpsp_trigger_process(struct ieee80211_hdr *hdr,
				    struct sta_info *sta, bool tx, bool acked)
{
	__le16 *qc = (__le16 *) ieee80211_get_qos_ctl(hdr);
	__le16 rspi = *qc & cpu_to_le16(IEEE80211_QOS_CTL_RSPI);
	__le16 eosp = *qc & cpu_to_le16(IEEE80211_QOS_CTL_EOSP);

	if (rspi || eosp ||
	    (!tx && sta->local_pm != NL80211_MESH_POWER_ACTIVE && !test_sta_flag(sta, WLAN_STA_MPSP_RECIPIENT)) ||
	    ( tx && acked && test_sta_flag(sta, WLAN_STA_PS_STA)    && !test_sta_flag(sta, WLAN_STA_MPSP_OWNER)))
		mps_dbg(sta->sdata, "%s MPSP trigger%s%s %pM\n", tx ? "tx" : "rx",
			rspi ? " RSPI" : "", eosp ? " EOSP" : "", sta->sta.addr);

	if (tx) {
		if (rspi && acked)
			test_and_set_mpsp_flag(sta, WLAN_STA_MPSP_RECIPIENT);

		if (eosp)
			test_and_clear_mpsp_flag(sta, WLAN_STA_MPSP_OWNER);
		else if (acked &&
			 test_sta_flag(sta, WLAN_STA_PS_STA) &&
			 !test_and_set_mpsp_flag(sta, WLAN_STA_MPSP_OWNER))
			mps_frame_deliver(sta, -1);
	} else {
		if (eosp)
			test_and_clear_mpsp_flag(sta, WLAN_STA_MPSP_RECIPIENT);
		else if (sta->local_pm != NL80211_MESH_POWER_ACTIVE)
			test_and_set_mpsp_flag(sta, WLAN_STA_MPSP_RECIPIENT);

		if (rspi && !test_and_set_mpsp_flag(sta, WLAN_STA_MPSP_OWNER))
			mps_frame_deliver(sta, -1);
	}
}

/**
 * ieee80211_mps_frame_release - release buffered frames in response to beacon
 *
 * @sta: mesh STA
 * @elems: beacon IEs
 *
 * For peers if we have individually-addressed frames buffered or the peer
 * indicates buffered frames, send a corresponding MPSP trigger frame. Since
 * we do not evaluate the awake window duration, QoS Nulls are used as MPSP
 * trigger frames. If the neighbour STA is not a peer, only send single frames.
 */
void ieee80211_mps_frame_release(struct sta_info *sta,
				 struct ieee802_11_elems *elems)
{
	int ac, buffer_local = 0;
	bool has_buffered = false;
	u16 awake_window = 0;

	/* TIM map only for LLID <= IEEE80211_MAX_AID */
	if (sta->plink_state == NL80211_PLINK_ESTAB)
		has_buffered = ieee80211_check_tim(elems->tim, elems->tim_len,
				le16_to_cpu(sta->llid) % IEEE80211_MAX_AID);

	if (has_buffered)
		mps_dbg(sta->sdata, "%pM indicates buffered frames\n",
			sta->sta.addr);

	if (elems->awake_window)
		awake_window = get_unaligned_le16(elems->awake_window);

	/* only transmit towards PS STA with announced awake window */
	if (test_sta_flag(sta, WLAN_STA_PS_STA) && !awake_window)
		return;

	for (ac = 0; ac < IEEE80211_NUM_ACS; ac++)
		buffer_local += skb_queue_len(&sta->ps_tx_buf[ac]) +
				skb_queue_len(&sta->tx_filtered[ac]);

	if (!has_buffered && !buffer_local)
		return;

	if (sta->plink_state == NL80211_PLINK_ESTAB)
		mpsp_trigger_send(sta, has_buffered, !buffer_local);
	else
		mps_frame_deliver(sta, 1);
}


/* mesh PS driver configuration and doze scheduling */

/*
 * DOC:
 * Generally, in mesh PS we have the issue that everything is per-STA. So
 * each time we have to check the PS status, we should check all sta_info.
 * To reduce computational load we use redundant information in ifmsh that is
 * just an or-combination of the information of the sta_info. Before going to
 * doze state we update that information. Wakeup is performed immediately.
 *
 * Since the device keeps its own sleep/wakeup cycle, we can never be sure
 * in which state it currently is. As a consequence some doze/wakeup calls to
 * the driver may be redundant. Despite these the device is supposed to keep a
 * sane state.
 */

/**
 * ieee80211_mps_hw_conf - check conditions for mesh PS and configure driver
 *
 * @local: local interface data
 */
void ieee80211_mps_hw_conf(struct ieee80211_local *local)
{
	struct ieee80211_sub_if_data *sdata;
	struct ieee80211_if_mesh *ifmsh;
	bool enable = true;

	if (!local->mps_ops)
		return;

	mutex_lock(&local->iflist_mtx);
	list_for_each_entry(sdata, &local->interfaces, list) {
		if (!ieee80211_sdata_running(sdata))
			continue;

		/* If an AP or any other non-mesh vif is found, disable PS */
		if (sdata->vif.type != NL80211_IFTYPE_MESH_POINT) {
			enable = false;
			break;
		}

		ifmsh = &sdata->u.mesh;

		/* check for non-peer power mode, check for links in active
		 * mode. Assume a valid power mode is set for each established
		 * peer link
		 */
		if (ifmsh->nonpeer_pm == NL80211_MESH_POWER_ACTIVE ||
		    ifmsh->ps_peers_light_sleep + ifmsh->ps_peers_deep_sleep
				< atomic_read(&ifmsh->estab_plinks)) {
			enable = false;
			break;
		}

		/* only doze once all beacons are received */
		set_bit(MPS_WAIT_FOR_BEACON, &ifmsh->ps_status_flags);
	}
	mutex_unlock(&local->iflist_mtx);

	if (local->mps_enabled == enable)
		return;

	local->mps_enabled = enable;
	if (enable)
		local->hw.conf.flags |= IEEE80211_CONF_PS;
	else
		local->hw.conf.flags &= ~IEEE80211_CONF_PS;
	ieee80211_hw_config(local, IEEE80211_CONF_CHANGE_PS);
}

/**
 * ieee80211_mps_schedule_update - update wakeup schedule for peer beacon
 *
 * @sta: mesh STA
 * @mgmt: beacon frame
 * @tim: TIM IE of beacon frame
 */
void ieee80211_mps_schedule_update(struct sta_info *sta,
				   struct ieee80211_mgmt *mgmt,
				   struct ieee80211_tim_ie *tim)
{
	struct ieee80211_sub_if_data *sdata = sta->sdata;
	struct ieee80211_if_mesh *ifmsh = &sdata->u.mesh;
	int skip = 1;
	unsigned long nexttbtt, margin = usecs_to_jiffies(MPS_TBTT_MARGIN);

	if (!sdata->local->mps_enabled ||
	    sta->plink_state != NL80211_PLINK_ESTAB)
		return;

	/* simple Deep Sleep implementation: only wake up for DTIM beacons */
	if (sta->local_pm == NL80211_MESH_POWER_DEEP_SLEEP &&
	    tim->dtim_count == 0)
		skip = tim->dtim_period;

	clear_sta_flag(sta, WLAN_STA_MPS_WAIT_FOR_BEACON);
	/* pending broadcasts after DTIM beacon? TODO reset after RX */
	if (tim->bitmap_ctrl & 0x01) {
		set_bit(MPS_WAIT_FOR_CAB, &ifmsh->ps_status_flags);
		set_sta_flag(sta, WLAN_STA_MPS_WAIT_FOR_CAB);
	} else {
		clear_sta_flag(sta, WLAN_STA_MPS_WAIT_FOR_CAB);
	}

	sta->last_beacon_rx = jiffies;
	sta->beacon_interval = usecs_to_jiffies(le16_to_cpu(
			mgmt->u.beacon.beacon_int) * 1024);
	nexttbtt = sta->last_beacon_rx + sta->beacon_interval * skip;
	sta->tbtt_wakeup = nexttbtt - margin;
	sta->tbtt_miss = nexttbtt + margin;

	mps_dbg(sdata, "updating %pM : BI=%d, DP=%d, DC=%d\n",
		sta->sta.addr, jiffies_to_usecs(sta->beacon_interval),
		tim->dtim_period, tim->dtim_count);

	mod_timer(&sta->mps_schedule_timer, sta->tbtt_wakeup);

	set_bit(MESH_WORK_PS_DOZE, &ifmsh->wrkq_flags);
	ieee80211_queue_work(&sdata->local->hw, &sdata->work);
}

/**
 * ieee80211_mps_sta_schedule_timer - timer for mesh PS doze/wakeup
 *
 * Used for both waking up and going to doze state again in case the beacon is
 * not received on time.
 */
void ieee80211_mps_sta_schedule_timer(unsigned long data)
{
	/* This STA is valid because free_sta_work() will
	 * del_timer_sync() this timer after having made sure
	 * it cannot be armed (by deleting the plink.)
	 */
	struct sta_info *sta = (struct sta_info *) data;
	struct ieee80211_sub_if_data *sdata = sta->sdata;
	struct ieee80211_if_mesh *ifmsh = &sdata->u.mesh;

	if (!sdata->local->mps_enabled ||
	    sta->plink_state != NL80211_PLINK_ESTAB)
		return;

	if (!test_sta_flag(sta, WLAN_STA_MPS_WAIT_FOR_BEACON)) {
		/* peer will send its beacon soon -> wakeup (and stay up) */
		set_sta_flag(sta, WLAN_STA_MPS_WAIT_FOR_BEACON);
		set_bit(MPS_WAIT_FOR_BEACON, &ifmsh->ps_status_flags);

		mps_dbg(sdata, "wakeup for %pM (margin %dus)\n",
			sta->sta.addr,
			jiffies_to_usecs(sta->tbtt_miss - sta->tbtt_wakeup));

		mod_timer(&sta->mps_schedule_timer, sta->tbtt_miss);

		set_bit(MESH_WORK_PS_WAKEUP, &ifmsh->wrkq_flags);
		ieee80211_queue_work(&sdata->local->hw, &sdata->work);
	} else {
		unsigned long margin, nexttbtt;
		int miss_cnt = -1;

		/* we missed the peer beacon this time */
		clear_sta_flag(sta, WLAN_STA_MPS_WAIT_FOR_BEACON);

		/* determine next TBTT based on last successful RX */
		nexttbtt = sta->last_beacon_rx;
		while (time_is_before_jiffies(nexttbtt)) {
			nexttbtt += sta->beacon_interval;
			miss_cnt++;
		}

		mps_dbg(sdata, "%pM beacon miss #%d\n", sta->sta.addr,
			miss_cnt);

		/* increase safety margin with miss_cnt */
		margin = usecs_to_jiffies(MPS_TBTT_MARGIN * miss_cnt);
		if (WARN_ON(margin >= sta->beacon_interval)) {
			set_sta_flag(sta, WLAN_STA_MPS_WAIT_FOR_BEACON);
			return;
		}

		sta->tbtt_wakeup = nexttbtt - margin;
		sta->tbtt_miss = nexttbtt + margin;

		mod_timer(&sta->mps_schedule_timer, sta->tbtt_wakeup);

		set_bit(MESH_WORK_PS_DOZE, &ifmsh->wrkq_flags);
		ieee80211_queue_work(&sdata->local->hw, &sdata->work);
	}
}

/**
 * ieee80211_mps_awake_window_start - start awake window on SWBA event
 *
 * @sdata: local mesh subif
 *
 * All tested hardware wakes up on its own on SWBA, so we currently do not
 * trigger a wakeup here
 */
void ieee80211_mps_awake_window_start(struct ieee80211_sub_if_data *sdata)
{
	struct ieee80211_if_mesh *ifmsh = &sdata->u.mesh;

	if (!sdata->local->mps_enabled)
		return;

	mps_dbg(sdata, "awake window start (%dTU)\n",
		ifmsh->mshcfg.dot11MeshAwakeWindowDuration);

	set_bit(MPS_IN_AWAKE_WINDOW, &ifmsh->ps_status_flags);
	mod_timer(&ifmsh->awake_window_end_timer, jiffies + usecs_to_jiffies(
			ifmsh->mshcfg.dot11MeshAwakeWindowDuration * 1024));
}

/**
 * ieee80211_mps_awake_window_end - timer for end of mesh Awake Window
 */
void ieee80211_mps_awake_window_end(unsigned long data)
{
	struct ieee80211_sub_if_data *sdata = (void *) data;
	struct ieee80211_if_mesh *ifmsh = &sdata->u.mesh;

	if (!sdata->local->mps_enabled)
		return;

	mps_dbg(sdata, "awake window end\n");
	clear_bit(MPS_IN_AWAKE_WINDOW, &ifmsh->ps_status_flags);

	set_bit(MESH_WORK_PS_DOZE, &ifmsh->wrkq_flags);
	ieee80211_queue_work(&sdata->local->hw, &sdata->work);
}

/**
 * ieee80211_mps_hw_doze - check conditions and trigger radio doze state
 *
 * @sdata: local mesh subif
 */
void ieee80211_mps_hw_doze(struct ieee80211_sub_if_data *sdata)
{
	struct ieee80211_local *local = sdata->local;
	struct ieee80211_if_mesh *ifmsh = &sdata->u.mesh;
	struct sta_info *sta;
	bool stay_awake = false;

	/* PS blocker:
	 * - mesh PS disabled
	 * - in Awake Window
	 * - in Mesh Peer Service Period
	 * - waiting for peer beacon
	 * - waiting for peer CAB frames
	 */
	if (!local->mps_enabled ||
	    test_bit(MPS_IN_AWAKE_WINDOW, &ifmsh->ps_status_flags) ||
	    atomic_read(&ifmsh->num_mpsp))
		return;

	mutex_lock(&local->sta_mtx);
	list_for_each_entry(sta, &local->sta_list, list) {
		if (!ieee80211_vif_is_mesh(&sta->sdata->vif) ||
		    !ieee80211_sdata_running(sta->sdata) ||
		    sta->plink_state != NL80211_PLINK_ESTAB) {
			continue;
		} else if (test_sta_flag(sta, WLAN_STA_MPS_WAIT_FOR_BEACON)) {
			mps_dbg(sdata, "waiting for beacon of %pM\n",
				sta->sta.addr);
			stay_awake = true;
			break;
		} else if (test_sta_flag(sta, WLAN_STA_MPS_WAIT_FOR_CAB)) {
			mps_dbg(sdata, "waiting for CAB from %pM\n",
				sta->sta.addr);
			stay_awake = true;
			break;
		}
	}
	mutex_unlock(&local->sta_mtx);

	if (stay_awake)
		return;

	clear_bit(MPS_WAIT_FOR_BEACON, &ifmsh->ps_status_flags);
	clear_bit(MPS_WAIT_FOR_CAB, &ifmsh->ps_status_flags);
	if (local->mps_ops)
		local->mps_ops->hw_doze(&sdata->local->hw);
}

int ieee80211_mps_hw_init(struct ieee80211_hw *hw,
			  const struct ieee80211_mps_ops *ops)
{
	struct ieee80211_local *local = hw_to_local(hw);

	local->mps_ops = ops;
	if (!ops)
		local->mps_enabled = false;

	printk(KERN_DEBUG "%sregistering mesh_ps_ops\n", ops ? "" : "de");

	return 0;
}
EXPORT_SYMBOL(ieee80211_mps_hw_init);

bool ieee80211_mps_hw_doze_allow(struct ieee80211_hw *hw)
{
	struct ieee80211_local *local = hw_to_local(hw);
	struct ieee80211_sub_if_data *sdata;
	struct ieee80211_if_mesh *ifmsh;
	bool allow = true;

	rcu_read_lock();
	list_for_each_entry_rcu(sdata, &local->interfaces, list) {
		if (!ieee80211_vif_is_mesh(&sdata->vif))
			continue;

		ifmsh = &sdata->u.mesh;
		if (atomic_read(&ifmsh->num_mpsp) ||
		    test_bit(MPS_IN_AWAKE_WINDOW, &ifmsh->ps_status_flags) ||
		    test_bit(MPS_WAIT_FOR_BEACON, &ifmsh->ps_status_flags) ||
		    test_bit(MPS_WAIT_FOR_CAB, &ifmsh->ps_status_flags)) {
			allow = false;
			break;
		}
	}
	rcu_read_unlock();

	return allow;
}
EXPORT_SYMBOL(ieee80211_mps_hw_doze_allow);
