<template>
  <NuxtLink
    v-if="
      authStore.userData &&
      hasPermissions(authStore.userData, 'clients', 'edit')
    "
    class="rounded bg-gray-100 p-2 align-middle transition hover:bg-red-800 hover:text-white dark:bg-neutral-600 dark:text-neutral-300 dark:hover:bg-red-800 dark:hover:text-white"
    :to="`/clients/${client.id}`"
  >
    <IconsEdit class="w-5" />
  </NuxtLink>
</template>

<script setup lang="ts">
defineProps<{
  client: LocalClient;
}>();

// changing a client's settings is the administrators' business
const authStore = useAuthStore();
</script>
