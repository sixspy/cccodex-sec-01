const { createApp, ref, onMounted, computed } = Vue;

createApp({
  setup() {
    const me = ref(null);
    const items = ref([]);
    const selectedId = ref(null);
    const detail = ref(null);
    const error = ref("");

    const selected = computed(() =>
      items.value.find((x) => x.id === selectedId.value) || detail.value
    );

    async function load() {
      error.value = "";
      const meRes = await fetch("/api/me");
      if (meRes.status === 401) {
        location.href = "/login";
        return;
      }
      me.value = await meRes.json();
      const listRes = await fetch("/api/alerts");
      const data = await listRes.json();
      items.value = data.items || [];
      if (!selectedId.value && items.value.length) {
        await openAlert(items.value[0].id);
      }
    }

    async function openAlert(id) {
      selectedId.value = id;
      const res = await fetch(`/api/alerts/${id}`);
      if (!res.ok) {
        error.value = "读取详情失败";
        return;
      }
      detail.value = await res.json();
    }

    async function logout() {
      await fetch("/api/logout", { method: "POST" });
      location.href = "/login";
    }

    onMounted(load);

    return { me, items, selectedId, selected, error, openAlert, logout };
  },
  template: `
    <div class="shell">
      <header class="topbar">
        <div class="stack">
          <p class="brand">SEC LAB · Vue</p>
          <h1>{{ me?.lab || '安全事件分流台' }}</h1>
          <p class="muted">当前用户 {{ me?.user || '-' }} · 告警列表与详情同源</p>
        </div>
        <button class="linkish" type="button" @click="logout">退出</button>
      </header>
      <p v-if="error" class="err">{{ error }}</p>
      <div class="grid">
        <section class="panel">
          <h2>待分流告警</h2>
          <table>
            <thead>
              <tr><th>编号</th><th>标题</th><th>指纹</th><th>级别</th><th>状态</th></tr>
            </thead>
            <tbody>
              <tr
                v-for="row in items"
                :key="row.id"
                class="clickable"
                :class="{ active: row.id === selectedId }"
                @click="openAlert(row.id)"
              >
                <td>{{ row.id }}</td>
                <td>{{ row.title }}</td>
                <td class="fp">{{ row.fingerprint }}</td>
                <td><span class="pill" :class="row.severity === '高' ? 'high' : 'mid'">{{ row.severity }}</span></td>
                <td>{{ row.status }}</td>
              </tr>
            </tbody>
          </table>
          <p v-if="!items.length" class="empty">暂无告警</p>
        </section>
        <section class="panel detail">
          <h2>告警详情</h2>
          <template v-if="selected">
            <dl>
              <dt>标题</dt><dd>{{ selected.title }}</dd>
              <dt>指纹</dt><dd class="fp">{{ selected.fingerprint }}</dd>
              <dt>级别</dt><dd>{{ selected.severity }}</dd>
              <dt>状态</dt><dd>{{ selected.status }}</dd>
              <dt>入库时间</dt><dd>{{ selected.created_at }}</dd>
            </dl>
          </template>
          <p v-else class="empty">选择左侧告警查看详情</p>
        </section>
      </div>
    </div>
  `,
}).mount("#app");
