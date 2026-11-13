const { createApp, ref, onMounted, computed } = Vue;

createApp({
  setup() {
    const me = ref(null);
    const board = ref({ policy: null, counts: {}, alerts: [], tickets: [], contentions: [], rules: [] });
    const error = ref("");
    const okMsg = ref("");
    const operator = ref("");
    const policyForm = ref({ rule: "merge", note: "" });
    const ingestForm = ref({ title: "", fingerprint: "", severity: "高" });
    const expandedTicket = ref(null);
    const expandedAlert = ref(null);
    const alertDetail = ref(null);
    const conclusions = ref({});

    const policyName = computed(
      () => board.value.policy?.rule_name || "尚未选定"
    );
    const pendingAlerts = computed(() =>
      board.value.alerts.filter((a) => a.status === "待认领")
    );

    function flash(msg, isErr = false) {
      if (isErr) {
        error.value = msg;
        okMsg.value = "";
      } else {
        okMsg.value = msg;
        error.value = "";
      }
      setTimeout(() => {
        if (!isErr) okMsg.value = "";
      }, 4000);
    }

    async function load() {
      error.value = "";
      const meRes = await fetch("/api/me");
      if (meRes.status === 401) {
        location.href = "/login";
        return;
      }
      me.value = await meRes.json();
      if (!operator.value) operator.value = me.value.user;
      const res = await fetch("/api/board");
      if (!res.ok) {
        flash("读取台面失败", true);
        return;
      }
      board.value = await res.json();
    }

    async function savePolicy() {
      const res = await fetch("/api/policy", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(policyForm.value),
      });
      const data = await res.json();
      if (!res.ok) return flash(data.detail || "策略设定失败", true);
      flash("当日策略已生效");
      return load();
    }

    async function ingest() {
      const res = await fetch("/api/alerts", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(ingestForm.value),
      });
      const data = await res.json();
      if (!res.ok) return flash(data.detail || "进台失败", true);
      ingestForm.value = { title: "", fingerprint: "", severity: "高" };
      flash("新告警已进台；若撞已结案指纹，旧处置单已回到待复核");
      return load();
    }

    async function claim(alert) {
      if (!alert.claimable) {
        return flash("级别空缺的告警既不许进合并，也不许被认领", true);
      }
      const res = await fetch(`/api/alerts/${alert.id}/claim`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ operator: operator.value }),
      });
      const data = await res.json();
      if (!res.ok) {
        await load();
        return flash(data.detail || "认领失败", true);
      }
      flash(`已由 ${operator.value} 认领进处置单 #${data.ticket.id}`);
      return load();
    }

    async function submitTicket(ticket) {
      const mode = board.value.policy?.rule;
      const res = await fetch(`/api/tickets/${ticket.id}/submit`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode, conclusion: conclusions.value[ticket.id] || "" }),
      });
      const data = await res.json();
      if (!res.ok) return flash(data.detail || "提交失败", true);
      flash(`处置单 #${ticket.id} 已结案`);
      return load();
    }

    async function showAlertDetail(alert) {
      if (expandedAlert.value === alert.id) {
        expandedAlert.value = null;
        return;
      }
      expandedAlert.value = alert.id;
      const res = await fetch(`/api/alerts/${alert.id}`);
      alertDetail.value = res.ok ? await res.json() : null;
    }

    function toggleTicket(id) {
      expandedTicket.value = expandedTicket.value === id ? null : id;
    }

    async function logout() {
      await fetch("/api/logout", { method: "POST" });
      location.href = "/login";
    }

    function statusPill(status) {
      if (status === "已结案") return "pill closed";
      if (status === "待复核") return "pill review";
      return "pill handling";
    }

    onMounted(load);

    return {
      me, board, error, okMsg, operator, policyForm, ingestForm,
      expandedTicket, expandedAlert, alertDetail, conclusions,
      policyName, pendingAlerts,
      load, savePolicy, ingest, claim, submitTicket,
      showAlertDetail, toggleTicket, logout, statusPill,
    };
  },
  template: `
    <div class="shell">
      <header class="topbar">
        <div class="stack">
          <p class="brand">SEC LAB · 安全事件分流台</p>
          <h1>{{ me?.lab || '安全事件分流台' }}</h1>
          <p class="muted">当前用户 {{ me?.user || '-' }} · 告警 → 合并组/串联链 → 处置单 闭环</p>
        </div>
        <button class="linkish" type="button" @click="logout">退出</button>
      </header>

      <p v-if="error" class="err">{{ error }}</p>
      <p v-if="okMsg" class="ok">{{ okMsg }}</p>

      <!-- 横排台账指标 -->
      <section class="stat-strip">
        <div class="stat" :class="{ 'stat-warn': !board.policy }">
          <p class="stat-label">今日策略名</p>
          <p class="stat-value">{{ policyName }}</p>
          <p v-if="board.policy" class="stat-sub">当天选定，不许换</p>
          <p v-else class="stat-sub">先去下方选定唯一规矩</p>
        </div>
        <div class="stat">
          <p class="stat-label">待认领数量</p>
          <p class="stat-value">{{ board.counts.pending ?? 0 }}</p>
          <p class="stat-sub">候审区 · 固定标题待认领</p>
        </div>
        <div class="stat">
          <p class="stat-label">处置中数量</p>
          <p class="stat-value">{{ board.counts.handling ?? 0 }}</p>
          <p class="stat-sub">已认领，尚未收口</p>
        </div>
        <div class="stat stat-review">
          <p class="stat-label">待复核数量</p>
          <p class="stat-value">{{ board.counts.review ?? 0 }}</p>
          <p class="stat-sub">结案后同指纹新告警涌进</p>
        </div>
        <div class="stat stat-closed">
          <p class="stat-label">已结案数量</p>
          <p class="stat-value">{{ board.counts.closed ?? 0 }}</p>
          <p class="stat-sub">处置已收口</p>
        </div>
      </section>

      <div class="grid">
        <div class="col">
          <!-- 策略页 -->
          <section class="panel">
            <h2>策略页 · 当日唯一规矩</h2>
            <template v-if="board.policy">
              <dl class="kv">
                <dt>策略名</dt><dd class="strong">{{ board.policy.rule_name }}</dd>
                <dt>生效日期</dt><dd>{{ board.policy.policy_date }}</dd>
                <dt>生效说明</dt><dd class="statement">{{ board.policy.statement }}</dd>
              </dl>
              <p class="muted small">当天不许换；处置没收口时生效说明禁止改动。</p>
            </template>
            <template v-else>
              <p class="muted">请选定唯一规矩并写进生效说明，提交后当天锁定：</p>
              <div class="form-row">
                <label v-for="r in board.rules" :key="r.code" class="rule-option">
                  <input type="radio" v-model="policyForm.rule" :value="r.code" />
                  <span>{{ r.name }}</span>
                </label>
              </div>
              <label>备注（可选，写进生效说明）
                <input v-model="policyForm.note" placeholder="例如：值班窗口补充说明" />
              </label>
              <button type="button" @click="savePolicy">写进生效说明并锁定</button>
            </template>
          </section>

          <!-- 候审区：标题固定为待认领 -->
          <section class="panel">
            <h2>待认领 <span class="count-badge">{{ board.counts.pending ?? 0 }}</span></h2>
            <table>
              <thead>
                <tr><th>编号</th><th>标题</th><th>指纹</th><th>级别</th><th>认领</th></tr>
              </thead>
              <tbody>
                <tr v-for="row in pendingAlerts" :key="row.id">
                  <td>{{ row.id }}</td>
                  <td>
                    <button class="linkish" type="button" @click="showAlertDetail(row)">{{ row.title }}</button>
                    <span v-if="!row.severity" class="pill no-sev">级别空缺 · 禁止认领</span>
                    <span v-for="fc in row.failed_claims" :key="fc.created_at" class="pill lost">
                      争抢落败：{{ fc.operator }}
                    </span>
                  </td>
                  <td class="fp">{{ row.fingerprint }}</td>
                  <td>
                    <span v-if="row.severity" class="pill" :class="row.severity === '高' ? 'high' : 'mid'">{{ row.severity }}</span>
                    <span v-else class="pill no-sev">空</span>
                  </td>
                  <td>
                    <button type="button" :disabled="!row.claimable" @click="claim(row)">认领进处置</button>
                  </td>
                </tr>
              </tbody>
            </table>
            <p v-if="!pendingAlerts.length" class="empty">待认领区已清空，告警都已进处置或复核</p>

            <div v-if="expandedAlert && alertDetail" class="sub-detail">
              <h3>告警 #{{ alertDetail.id }} 详情</h3>
              <dl class="kv">
                <dt>状态</dt><dd>{{ alertDetail.status }}</dd>
                <dt>指纹</dt><dd class="fp">{{ alertDetail.fingerprint }}</dd>
                <dt>级别</dt><dd>{{ alertDetail.severity || '（空）' }}</dd>
                <dt>入库时间</dt><dd>{{ alertDetail.created_at }}</dd>
                <dt>所属处置单</dt><dd>{{ alertDetail.ticket_id ? '#' + alertDetail.ticket_id : '暂无' }}</dd>
              </dl>
              <p v-if="alertDetail.ticket" class="muted small">
                走法：{{ alertDetail.ticket.mode_name }} · 单据状态：{{ alertDetail.ticket.status }}
              </p>
              <ul v-if="alertDetail.claim_history.length" class="claim-log">
                <li v-for="(h, i) in alertDetail.claim_history" :key="i">
                  {{ h.operator }} · {{ h.result === 'success' ? '认领成功' : '争抢失败' }} · {{ h.created_at }}
                </li>
              </ul>
            </div>
          </section>

          <!-- 新告警进台 -->
          <section class="panel">
            <h2>新告警进台（同指纹可触发待复核）</h2>
            <div class="form-grid">
              <label>标题<input v-model="ingestForm.title" placeholder="告警标题" /></label>
              <label>指纹<input v-model="ingestForm.fingerprint" placeholder="如 auth.bruteforce" class="fp-input" /></label>
              <label>级别（留空即级别空缺）
                <select v-model="ingestForm.severity">
                  <option value="高">高</option>
                  <option value="中">中</option>
                  <option value="低">低</option>
                  <option value="">空（禁止认领）</option>
                </select>
              </label>
            </div>
            <button type="button" @click="ingest">进台</button>
          </section>
        </div>

        <div class="col">
          <!-- 处置单卡片 -->
          <section class="panel">
            <h2>处置单（合并组 / 串联链）</h2>
            <p v-if="!board.tickets.length" class="empty">尚无处置单，先在待认领区认领告警</p>
            <article v-for="t in board.tickets" :key="t.id" class="ticket" :class="{ review: t.status === '待复核', closed: t.status === '已结案' }">
              <header class="ticket-head" @click="toggleTicket(t.id)">
                <div>
                  <strong>处置单 #{{ t.id }}</strong>
                  <span class="pill" :class="t.mode === 'merge' ? 'mode-merge' : 'mode-chain'">{{ t.mode_name }}</span>
                  <span :class="statusPill(t.status)">{{ t.status }}</span>
                  <span v-for="fc in t.failed_claims" :key="fc.created_at" class="pill lost">争抢落败：{{ fc.operator }}</span>
                </div>
                <span class="muted small fp">{{ t.fingerprint }} · 展开{{ expandedTicket === t.id ? '▲' : '▼' }}</span>
              </header>

              <div v-if="expandedTicket === t.id" class="ticket-body">
                <dl class="kv">
                  <dt>认领操作员</dt><dd>{{ t.owner }}</dd>
                  <dt>成员告警</dt><dd>{{ t.alerts.length }} 条</dd>
                  <dt v-if="t.conclusion">收口结论</dt><dd v-if="t.conclusion">{{ t.conclusion }}</dd>
                </dl>

                <!-- 合并组展开 -->
                <div v-if="t.mode === 'merge'" class="chain-box">
                  <h3>合并组 · 同指纹收成一单</h3>
                  <ul class="member-list">
                    <li v-for="a in t.alerts" :key="a.id">
                      #{{ a.id }} {{ a.title }}
                      <span class="pill" :class="a.severity === '高' ? 'high' : 'mid'">{{ a.severity || '空' }}</span>
                      <span class="muted small">{{ a.status }}</span>
                    </li>
                  </ul>
                </div>

                <!-- 串联链展开：链条互指 -->
                <div v-else class="chain-box">
                  <h3>串联链 {{ t.chain?.chain_id }} · 分单再串联</h3>
                  <ol class="chain-list">
                    <li v-for="p in t.chain?.peers || []" :key="p.id" :class="{ current: p.id === t.id }">
                      <span :class="p.id === t.id ? 'strong' : ''">处置单 #{{ p.id }}</span>
                      · {{ p.status }} · {{ p.owner }}
                      <span v-if="p.id === t.id" class="pill mode-chain">当前单</span>
                    </li>
                  </ol>
                  <p class="muted small">
                    上一单：{{ t.chain?.prev_id ? '#' + t.chain.prev_id : '无' }} ｜
                    下一单：{{ t.chain?.next_id ? '#' + t.chain.next_id : '无（链条末尾）' }}
                  </p>
                </div>

                <div v-if="t.failed_claims.length" class="contention-box">
                  <h3>争抢落败提示</h3>
                  <ul>
                    <li v-for="(fc, i) in t.failed_claims" :key="i">
                      告警 #{{ fc.alert_id }} · 操作员 {{ fc.operator }} 争抢失败 · {{ fc.created_at }}
                    </li>
                  </ul>
                </div>

                <div v-if="t.status !== '已结案'" class="submit-box">
                  <label>收口结论
                    <input v-model="conclusions[t.id]" placeholder="处置结论" />
                  </label>
                  <button type="button" @click="submitTicket(t)">
                    按当日策略（{{ policyName }}）提交收口
                  </button>
                  <p v-if="t.status === '待复核'" class="warn-text">
                    同指纹新告警已涌进，旧结案不再充当完成，请复核后重新收口。
                  </p>
                </div>
                <p v-else class="muted small">已结案于 {{ t.closed_at }}；同指纹再来新告警会回到待复核。</p>
              </div>
            </article>
          </section>

          <!-- 争抢落败总览 -->
          <section class="panel contention-panel">
            <h2>争抢落败记录</h2>
            <p v-if="!board.contentions.length" class="empty">暂无争抢</p>
            <ul v-else class="claim-log">
              <li v-for="(c, i) in board.contentions" :key="i">
                <span class="pill lost">争抢落败</span>
                告警 #{{ c.alert_id }}（{{ c.title }} · <span class="fp">{{ c.fingerprint }}</span>）
                操作员 {{ c.operator }} · {{ c.created_at }}
              </li>
            </ul>
          </section>
        </div>
      </div>
    </div>
  `,
}).mount("#app");
