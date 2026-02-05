<script setup lang="ts">
import { getSdwanVersion } from '~/composables/backend'

const { t } = useI18n()

const etVersion = ref('')

onMounted(async () => {
  etVersion.value = await getSdwanVersion()
})
</script>

<template>
  <Card>
    <template #title>
      SDWAN - {{ t('about.version') }}: {{ etVersion }}
    </template>
    <template #content>
      <p class="mb-1">
        {{ t('about.description') }}
      </p>
    </template>
  </Card>
</template>

<style scoped lang="postcss">
</style>
