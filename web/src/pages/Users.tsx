import { useEffect, useState } from 'react'
import {
  Table,
  Button,
  Space,
  Modal,
  Form,
  Input,
  Switch,
  message,
  Popconfirm,
  Tag,
} from 'antd'
import { PlusOutlined, EditOutlined, DeleteOutlined } from '@ant-design/icons'
import { usersApi, User } from '../api/client'

export default function Users() {
  const [loading, setLoading] = useState(false)
  const [users, setUsers] = useState<User[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(10)
  const [modalOpen, setModalOpen] = useState(false)
  const [editingUser, setEditingUser] = useState<User | null>(null)
  const [form] = Form.useForm()

  const fetchUsers = async () => {
    setLoading(true)
    try {
      const res = await usersApi.list({ page, page_size: pageSize })
      setUsers(res.data.data)
      setTotal(res.data.total)
    } catch (error) {
      message.error('Failed to fetch users')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchUsers()
  }, [page, pageSize])

  const handleCreate = () => {
    setEditingUser(null)
    form.resetFields()
    form.setFieldsValue({ owner: 'built-in', is_admin: false })
    setModalOpen(true)
  }

  const handleEdit = (user: User) => {
    setEditingUser(user)
    form.setFieldsValue(user)
    setModalOpen(true)
  }

  const handleDelete = async (id: string) => {
    try {
      await usersApi.delete(id)
      message.success('User deleted')
      fetchUsers()
    } catch (error) {
      message.error('Failed to delete user')
    }
  }

  const handleSubmit = async () => {
    try {
      const values = await form.validateFields()
      if (editingUser) {
        await usersApi.update(editingUser.id, values)
        message.success('User updated')
      } else {
        await usersApi.create(values)
        message.success('User created')
      }
      setModalOpen(false)
      fetchUsers()
    } catch (error: any) {
      if (error.errorFields) return
      message.error(error.response?.data?.details || 'Operation failed')
    }
  }

  const columns = [
    {
      title: 'Name',
      dataIndex: 'name',
      key: 'name',
    },
    {
      title: 'Display Name',
      dataIndex: 'display_name',
      key: 'display_name',
    },
    {
      title: 'Organization',
      dataIndex: 'owner',
      key: 'owner',
    },
    {
      title: 'Email',
      dataIndex: 'email',
      key: 'email',
    },
    {
      title: 'Admin',
      dataIndex: 'is_admin',
      key: 'is_admin',
      render: (isAdmin: boolean) =>
        isAdmin ? <Tag color="red">Admin</Tag> : <Tag>User</Tag>,
    },
    {
      title: 'Created',
      dataIndex: 'created_at',
      key: 'created_at',
      render: (date: string) => new Date(date).toLocaleDateString(),
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_: any, record: User) => (
        <Space>
          <Button icon={<EditOutlined />} onClick={() => handleEdit(record)} />
          <Popconfirm
            title="Delete this user?"
            onConfirm={() => handleDelete(record.id)}
          >
            <Button icon={<DeleteOutlined />} danger />
          </Popconfirm>
        </Space>
      ),
    },
  ]

  return (
    <div>
      <div className="page-header">
        <h2 className="page-title">Users</h2>
        <Button type="primary" icon={<PlusOutlined />} onClick={handleCreate}>
          Add User
        </Button>
      </div>

      <Table
        columns={columns}
        dataSource={users}
        rowKey="id"
        loading={loading}
        pagination={{
          current: page,
          pageSize,
          total,
          onChange: (p, ps) => {
            setPage(p)
            setPageSize(ps)
          },
        }}
      />

      <Modal
        title={editingUser ? 'Edit User' : 'Create User'}
        open={modalOpen}
        onOk={handleSubmit}
        onCancel={() => setModalOpen(false)}
      >
        <Form form={form} layout="vertical">
          <Form.Item
            name="owner"
            label="Organization"
            rules={[{ required: true }]}
          >
            <Input />
          </Form.Item>
          <Form.Item
            name="name"
            label="Username"
            rules={[{ required: true }]}
          >
            <Input disabled={!!editingUser} />
          </Form.Item>
          <Form.Item
            name="display_name"
            label="Display Name"
            rules={[{ required: true }]}
          >
            <Input />
          </Form.Item>
          {!editingUser && (
            <Form.Item
              name="password"
              label="Password"
              rules={[{ required: true, min: 6 }]}
            >
              <Input.Password />
            </Form.Item>
          )}
          <Form.Item name="email" label="Email">
            <Input />
          </Form.Item>
          <Form.Item name="phone" label="Phone">
            <Input />
          </Form.Item>
          <Form.Item name="is_admin" label="Admin" valuePropName="checked">
            <Switch />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  )
}
