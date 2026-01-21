import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  headers: {
    'Content-Type': 'application/json',
  },
})

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token')
      localStorage.removeItem('user')
      window.location.href = '/login'
    }
    return Promise.reject(error)
  }
)

export interface User {
  id: string
  owner: string
  name: string
  display_name: string
  email?: string
  phone?: string
  avatar?: string
  is_admin: boolean
  created_at: string
  updated_at: string
}

export interface Organization {
  id: string
  owner: string
  name: string
  display_name: string
  website_url?: string
  favicon?: string
  password_type: string
  default_avatar?: string
  created_at: string
  updated_at: string
}

export interface Application {
  id: string
  owner: string
  name: string
  display_name: string
  logo?: string
  homepage_url?: string
  description?: string
  organization: string
  client_id: string
  client_secret: string
  redirect_uris: string
  token_format: string
  expire_in_hours: number
  created_at: string
  updated_at: string
}

export interface Role {
  id: string
  owner: string
  name: string
  display_name: string
  description?: string
  is_enabled: boolean
  created_at: string
  updated_at: string
}

export interface Permission {
  id: string
  owner: string
  name: string
  display_name: string
  description?: string
  resource_type: string
  resources: string
  actions: string
  effect: string
  is_enabled: boolean
  created_at: string
  updated_at: string
}

export interface Policy {
  ptype: string
  v0: string
  v1: string
  v2: string
  v3?: string
  v4?: string
}

export interface ListResponse<T> {
  data: T[]
  total: number
  page: number
  page_size: number
}

export interface LoginRequest {
  owner: string
  name: string
  password: string
}

export interface SignupRequest {
  owner: string
  name: string
  password: string
  display_name: string
  email?: string
  phone?: string
}

export interface LoginResponse {
  token: string
  token_type: string
  expires_in: number
  user: User
}

// Auth API
export const authApi = {
  login: (data: LoginRequest) => api.post<LoginResponse>('/login', data),
  signup: (data: SignupRequest) => api.post<LoginResponse>('/signup', data),
  logout: () => api.post('/logout'),
  getAccount: () => api.get<User>('/get-account'),
}

// Users API
export const usersApi = {
  list: (params?: { owner?: string; page?: number; page_size?: number }) =>
    api.get<ListResponse<User>>('/users', { params }),
  get: (id: string) => api.get<User>(`/users/${id}`),
  create: (data: Partial<User> & { password: string }) => api.post<User>('/users', data),
  update: (id: string, data: Partial<User>) => api.put<User>(`/users/${id}`, data),
  delete: (id: string) => api.delete(`/users/${id}`),
}

// Organizations API
export const organizationsApi = {
  list: (params?: { owner?: string; page?: number; page_size?: number }) =>
    api.get<ListResponse<Organization>>('/organizations', { params }),
  get: (id: string) => api.get<Organization>(`/organizations/${id}`),
  create: (data: Partial<Organization>) => api.post<Organization>('/organizations', data),
  update: (id: string, data: Partial<Organization>) =>
    api.put<Organization>(`/organizations/${id}`, data),
  delete: (id: string) => api.delete(`/organizations/${id}`),
}

// Applications API
export const applicationsApi = {
  list: (params?: { owner?: string; organization?: string; page?: number; page_size?: number }) =>
    api.get<ListResponse<Application>>('/applications', { params }),
  get: (id: string) => api.get<Application>(`/applications/${id}`),
  create: (data: Partial<Application>) => api.post<Application>('/applications', data),
  update: (id: string, data: Partial<Application>) =>
    api.put<Application>(`/applications/${id}`, data),
  delete: (id: string) => api.delete(`/applications/${id}`),
}

// Roles API
export const rolesApi = {
  list: (params?: { owner?: string; page?: number; page_size?: number }) =>
    api.get<ListResponse<Role>>('/roles', { params }),
  get: (id: string) => api.get<Role>(`/roles/${id}`),
  create: (data: Partial<Role>) => api.post<Role>('/roles', data),
  update: (id: string, data: Partial<Role>) => api.put<Role>(`/roles/${id}`, data),
  delete: (id: string) => api.delete(`/roles/${id}`),
  assign: (user_id: string, role_id: string) => api.post('/roles/assign', { user_id, role_id }),
  getUserRoles: (userId: string) => api.get<Role[]>(`/roles/user/${userId}`),
}

// Permissions API
export const permissionsApi = {
  list: (params?: { owner?: string; page?: number; page_size?: number }) =>
    api.get<ListResponse<Permission>>('/permissions', { params }),
  get: (id: string) => api.get<Permission>(`/permissions/${id}`),
  create: (data: Partial<Permission>) => api.post<Permission>('/permissions', data),
  update: (id: string, data: Partial<Permission>) =>
    api.put<Permission>(`/permissions/${id}`, data),
  delete: (id: string) => api.delete(`/permissions/${id}`),
  assign: (role_id: string, permission_id: string) =>
    api.post('/permissions/assign', { role_id, permission_id }),
  getRolePermissions: (roleId: string) => api.get<Permission[]>(`/permissions/role/${roleId}`),
}

// Policies API
export const policiesApi = {
  list: () => api.get<{ data: Policy[] }>('/policies'),
  add: (policy: { ptype: string; v0: string; v1: string; v2: string }) =>
    api.post('/policies', policy),
  remove: (policy: { ptype: string; v0: string; v1: string; v2: string }) =>
    api.delete('/policies', { data: policy }),
  enforce: (sub: string, obj: string, act: string) =>
    api.post<{ allowed: boolean }>('/enforce', { sub, obj, act }),
}

export default api
