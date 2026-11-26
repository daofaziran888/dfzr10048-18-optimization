<template>
  <section class="page" :data-module="meta.key">
    <header class="page-head">
      <div>
        <h2>{{ meta.name }}</h2>
        <p class="page-desc">{{ meta.desc }}</p>
      </div>
      <div class="page-actions">
        <button class="btn primary" data-testid="open-create" type="button" @click="openCreate">
          登记{{ meta.entity }}
        </button>
        <button class="btn" data-testid="export" type="button" @click="exportRows">
          导出{{ meta.name }}清单
        </button>
      </div>
    </header>

    <section v-if="meta.key === 'delivery_receipt'" class="receipt-panel" data-testid="receipt-consistency-panel">
      <h3>断点导出 · 归属鉴权 · 签收复验</h3>
      <div class="filter-bar">
        <label class="filter-item">
          <span>接收方标识</span>
          <input v-model="receiptReceiver" data-testid="receipt-receiver-input" placeholder="回执归属接收方" />
        </label>
        <label class="filter-item">
          <span>接收方凭据</span>
          <input v-model="receiptCredential" data-testid="receipt-credential-input" placeholder="仅凭据归属接收方可访问" />
        </label>
        <label class="filter-item">
          <span>回执编号</span>
          <input v-model="receiptId" data-testid="receipt-id-input" placeholder="例如 DLRC-0001" />
        </label>
        <label class="filter-item">
          <span>批次编号</span>
          <input v-model="receiptBatch" data-testid="receipt-batch-input" placeholder="同一批导出凭证" />
        </label>
        <label class="filter-item">
          <span>补签区间</span>
          <input v-model="supplementRange" data-testid="supplement-range-input" placeholder="61-80" />
        </label>
      </div>
      <div class="page-actions receipt-actions">
        <button class="btn" data-testid="issue-credential" type="button" @click="issueReceiptCredential">签发/登记凭据</button>
        <button class="btn" data-testid="create-receipt-batch" type="button" @click="createReceiptBatch">建立同批凭证</button>
        <button class="btn primary" data-testid="resume-receipt-export" type="button" @click="resumeReceiptExport">断点续下未收回执</button>
        <button class="btn" data-testid="claim-supplement" type="button" @click="claimSupplement">单独领取补签</button>
        <button class="btn" data-testid="review-receipt" type="button" @click="reviewReceipt">原凭据复查记录</button>
      </div>

      <div class="verify-grid">
        <label class="filter-item">
          <span>C 版本一实际字幕（每行一条）</span>
          <textarea v-model="subtitleVersionA" data-testid="subtitle-version-a" rows="5" placeholder="粘贴第一版实际字幕"></textarea>
        </label>
        <label class="filter-item">
          <span>C 版本二实际字幕（每行一条）</span>
          <textarea v-model="subtitleVersionB" data-testid="subtitle-version-b" rows="5" placeholder="粘贴改字版实际字幕"></textarea>
        </label>
      </div>
      <div class="page-actions receipt-actions">
        <button class="btn" data-testid="freeze-pack-content" type="button" @click="freezePackContent">用版本一冻结当时字节</button>
        <button class="btn primary" data-testid="verify-two-versions" type="button" @click="verifyTwoVersions">两版 C 分别验签</button>
        <button class="btn" data-testid="verify-current-receipt" type="button" @click="verifyCurrentReceipt">只验当前文本</button>
      </div>

      <p v-if="receiptFeedback" class="receipt-feedback" data-testid="receipt-feedback">{{ receiptFeedback }}</p>
      <p v-if="receiptError" class="error-text" data-testid="receipt-error">{{ receiptError }}</p>
      <pre v-if="receiptResult" class="receipt-result" data-testid="receipt-result">{{ JSON.stringify(receiptResult, null, 2) }}</pre>
    </section>

    <div class="stat-row">
      <article v-for="item in stats" :key="item.label" class="stat-card">
        <span class="stat-label">{{ item.label }}</span>
        <strong class="stat-value">{{ item.value }}</strong>
      </article>
    </div>

    <p class="status-legend">
      <span v-for="item in statusSummary" :key="item.status" class="legend-item">
        {{ item.status }}：{{ item.count }}
      </span>
    </p>

    <form class="filter-bar" @submit.prevent="reload">
      <label v-for="field in filterFields" :key="field" class="filter-item">
        <span>{{ field }}</span>
        <input v-model="filters[field]" :data-testid="`filter-${field}`" :placeholder="`按${field}检索`" />
      </label>
      <button class="btn" data-testid="query" type="submit">查询</button>
      <button class="btn ghost" data-testid="reset" type="button" @click="resetFilters">重置条件</button>
    </form>

    <table class="data-table">
      <thead>
        <tr>
          <th v-for="column in meta.fields" :key="column">{{ column }}</th>
          <th>当前状态</th>
          <th>可执行动作</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="row in rows" :key="String(row.id)" :data-testid="`row-${row.id}`" :data-status="String(row.status)">
          <td v-for="column in meta.fields" :key="column">{{ row[column] ?? '—' }}</td>
          <td>{{ row.status }}</td>
          <td class="row-actions">
            <button
              v-for="action in meta.actions"
              :key="action"
              class="link"
              type="button"
              :data-testid="`action-${row.id}-${action}`"
              @click="runAction(action, row)"
            >
              {{ action }}
            </button>
          </td>
        </tr>
        <tr v-if="!rows.length">
          <td :colspan="meta.fields.length + 2" class="empty-state">
            暂无{{ meta.name }}数据，可先登记{{ meta.entity }}
          </td>
        </tr>
      </tbody>
    </table>

    <div v-if="showCreate" class="modal-backdrop" data-testid="create-modal">
      <form class="modal" @submit.prevent="submitCreate">
        <h3>登记{{ meta.entity }}</h3>
        <label v-for="field in meta.fields" :key="field" class="create-field">
          <span>{{ field }}</span>
          <input v-model="createValues[field]" :data-testid="`create-${field}`" required />
        </label>
        <div class="page-actions">
          <button class="btn" type="button" @click="showCreate = false">取消</button>
          <button class="btn primary" data-testid="submit-create" type="submit" :disabled="creating">
            {{ creating ? '提交中…' : '确认登记' }}
          </button>
        </div>
      </form>
    </div>

    <footer class="page-foot">
      <span>共 {{ total }} 条{{ meta.name }}记录</span>
      <span v-if="errorMessage" class="error-text">{{ errorMessage }}</span>
    </footer>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'

import {
  createEntry,
  downloadEntries,
  listEntries,
  moduleMeta,
  runAction as applyAction,
} from '@/api/backend-service'
import type { EntryRow } from '@/data/types'
import { request } from '@/api/client'

const props = defineProps<{ moduleKey: string }>()
const meta = moduleMeta(props.moduleKey)
const rows = ref<EntryRow[]>([])
const total = ref(0)
const errorMessage = ref('')
const filters = ref<Record<string, string>>({})
const filterFields = meta.fields.slice(0, 3)
const showCreate = ref(false)
const creating = ref(false)
const createValues = ref<Record<string, string>>({})
const receiptCredential = ref('')
const receiptReceiver = ref('')
const receiptId = ref('')
const receiptBatch = ref('')
const supplementRange = ref('61-80')
const subtitleVersionA = ref('')
const subtitleVersionB = ref('')
const receiptResult = ref<Record<string, unknown> | null>(null)
const receiptFeedback = ref('')
const receiptError = ref('')
const stats = computed(() => [
  { label: meta.metrics[0], value: total.value },
  { label: meta.metrics[1], value: rows.value.filter((row) => row.status === meta.statuses[1]).length },
  {
    label: meta.metrics[2],
    value: rows.value.filter((row) => row.status === meta.statuses[meta.statuses.length - 1]).length,
  },
])
const statusSummary = computed(() =>
  meta.statuses.map((status) => ({
    status,
    count: rows.value.filter((row) => String(row.status) === status).length,
  })),
)

function resetFilters() {
  filters.value = {}
  void reload()
}

async function exportRows() {
  errorMessage.value = ''
  try {
    const exportFilters: Record<string, string> = { ...filters.value }
    if (meta.key === 'delivery_receipt') {
      if (receiptCredential.value) exportFilters.credential = receiptCredential.value
      if (receiptReceiver.value) exportFilters.receiver_id = receiptReceiver.value
      if (receiptBatch.value) exportFilters.batch_id = receiptBatch.value
      if (supplementRange.value) exportFilters.range = supplementRange.value
      if (receiptCredential.value || receiptBatch.value) exportFilters.resume = '1'
    }
    await downloadEntries(meta.key, exportFilters)
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '导出失败'
  }
}

function openCreate() {
  createValues.value = Object.fromEntries(meta.fields.map((field) => [field, '']))
  errorMessage.value = ''
  showCreate.value = true
}

async function submitCreate() {
  creating.value = true
  errorMessage.value = ''
  try {
    const result = await createEntry(meta.key, createValues.value)
    if (!result.ok) throw new Error(result.message)
    showCreate.value = false
    await reload()
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '登记失败'
  } finally {
    creating.value = false
  }
}

async function runAction(action: string, row: EntryRow) {
  errorMessage.value = ''
  try {
    const result = await applyAction(meta.key, Number(row.id), action)
    if (!result.ok) throw new Error(result.message)
    await reload()
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '操作失败'
  }
}

async function receiptPost(path: string, body: Record<string, unknown>): Promise<any> {
  const response = await request(`/api/delivery_receipt${path}`, {
    method: 'POST',
    body: JSON.stringify(body),
  })
  const data = await response.json().catch(() => ({}))
  if (!response.ok) {
    throw new Error(typeof data.detail === 'string' ? data.detail : '回执一致性接口拒绝了本次请求')
  }
  return data
}

async function receiptGet(path: string): Promise<any> {
  const response = await request(`/api/delivery_receipt${path}`)
  const data = await response.json().catch(() => ({}))
  if (!response.ok) {
    throw new Error(typeof data.detail === 'string' ? data.detail : '回执一致性接口拒绝了本次请求')
  }
  return data
}

function presentReceiptResult(result: Record<string, unknown>, feedback?: string) {
  receiptResult.value = result
  if (typeof result.batch_id === 'string' && result.batch_id) {
    receiptBatch.value = result.batch_id
  }
  if (typeof result.receipt_id === 'string' && result.receipt_id && !receiptId.value) {
    receiptId.value = result.receipt_id
  }
  receiptFeedback.value = feedback || String(result.message || '操作完成')
}

async function runReceiptCall(label: string, fn: () => Promise<Record<string, unknown>>) {
  receiptError.value = ''
  receiptFeedback.value = ''
  try {
    const result = await fn()
    presentReceiptResult(result, `${label}：${String(result.message || '完成')}`)
  } catch (error) {
    receiptResult.value = null
    receiptError.value = error instanceof Error ? error.message : `${label}失败`
  }
}

function issueReceiptCredential() {
  return runReceiptCall('签发凭据', () => receiptPost('/credentials', {
    receipt_id: receiptId.value,
    receiver_id: receiptReceiver.value,
    token: receiptCredential.value || undefined,
    credential: receiptCredential.value || undefined,
  }))
}

function createReceiptBatch() {
  return runReceiptCall('建立批次', () => receiptPost('/batches', {
    credential: receiptCredential.value,
    receiver_id: receiptReceiver.value || undefined,
    batch_id: receiptBatch.value || undefined,
    receipt_ids: receiptId.value ? [receiptId.value] : undefined,
  }))
}

function resumeReceiptExport() {
  const params = new URLSearchParams()
  if (receiptCredential.value) params.set('credential', receiptCredential.value)
  if (receiptBatch.value) params.set('batch_id', receiptBatch.value)
  if (supplementRange.value) params.set('range', supplementRange.value)
  return runReceiptCall('断点续下', () => receiptPost('/exports', {
    credential: receiptCredential.value,
    batch_id: receiptBatch.value || undefined,
    receiver_id: receiptReceiver.value || undefined,
    range: supplementRange.value || undefined,
  }).then((data) => {
    // 同时保留 GET 导出入口可核对的查询参数形态，便于页面刷新后复现。
    window.history.replaceState(null, '', `?${params.toString()}`)
    return data
  }))
}

function claimSupplement() {
  return runReceiptCall('领取补签', () => receiptPost('/supplements/claim', {
    credential: receiptCredential.value,
    batch_id: receiptBatch.value || undefined,
    receipt_id: receiptId.value || undefined,
    range: supplementRange.value || undefined,
  }))
}

function reviewReceipt() {
  const params = new URLSearchParams()
  params.set('credential', receiptCredential.value)
  if (receiptReceiver.value) params.set('receiver_id', receiptReceiver.value)
  return runReceiptCall('复查记录', () => receiptGet(`/review?receipt_id=${encodeURIComponent(receiptId.value)}&${params.toString()}`))
}

function subtitleLines(text: string): string[] {
  return text.replace(/\s+$/g, '').split('\n')
}

function freezePackContent() {
  return runReceiptCall('冻结旧包字节', () => receiptPost('/content', {
    receipt_id: receiptId.value || undefined,
    credential: receiptCredential.value || undefined,
    lines: subtitleLines(subtitleVersionA.value),
    version: 'C-frozen',
  }))
}

function verifyTwoVersions() {
  return runReceiptCall('两版验签', () => receiptPost('/verify-signatures', {
    credential: receiptCredential.value,
    receipt_id: receiptId.value || undefined,
    contents: [subtitleLines(subtitleVersionA.value), subtitleLines(subtitleVersionB.value)],
    versions: ['C-version-A', 'C-version-B'],
  }))
}

function verifyCurrentReceipt() {
  return runReceiptCall('当前文本验签', () => receiptPost('/verify', {
    credential: receiptCredential.value,
    receipt_id: receiptId.value || undefined,
    lines: subtitleLines(subtitleVersionA.value || subtitleVersionB.value),
  }))
}

async function reload() {
  errorMessage.value = ''
  try {
    const payload = await listEntries(meta.key, filters.value)
    rows.value = payload.items
    total.value = payload.total
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '业务列表读取失败'
  }
}

onMounted(reload)
</script>

<style scoped>
.receipt-panel {
  margin: 16px 0;
  padding: 16px;
  border: 1px solid var(--border-color, #d9dee8);
  border-radius: 12px;
  background: rgba(255, 255, 255, 0.72);
}

.receipt-panel h3 {
  margin: 0 0 12px;
}

.receipt-actions {
  flex-wrap: wrap;
  margin: 12px 0;
}

.verify-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 12px;
}

.verify-grid textarea {
  width: 100%;
  border: 1px solid #cfd6e4;
  border-radius: 8px;
  padding: 8px;
  font: inherit;
  resize: vertical;
}

.receipt-result {
  max-height: 320px;
  overflow: auto;
  padding: 12px;
  border-radius: 8px;
  background: #101828;
  color: #d0d5dd;
  font-size: 12px;
  white-space: pre-wrap;
  word-break: break-word;
}

.receipt-feedback {
  color: #067647;
  font-weight: 600;
}
</style>
