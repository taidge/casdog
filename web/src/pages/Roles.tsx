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
import { rolesApi, Role } from '../api/client'

export default function Roles() {
  const [loading, setLoading] = useState(false)
  const [roles, setRoles] = useState<Role[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(10)
  const [modalOpen, setModalOpen] = useState(false)
  const [editingRole, setEditingRole] = useState<Role | null>(null)
  const [form] = Form.useForm()

  const fetchRoles = async () => {
    setLoading(true)
    try {
      const res = await rolesApi.list({ page, page_size: pageSize })
      setRoles(res.data.data)
      setTotal(res.data.total)
    } catch (error) {
      message.error('Failed to fetch roles')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchRoles()
  }, [page, pageSize])

  const handleCreate = () => {
    setEditingRole(null)
    form.resetFields()
    form.setFieldsValue({ owner: 'built-in', is_enabled: true })
    setModalOpen(true)
  }

  const handleEdit = (role: Role) => {
    setEditingRole(role)
    form.setFieldsValue(role)
    setModalOpen(true)
  }

  const handleDelete = async (id: string) => {
    try {
      await rolesApi.delete(id)
      message.success('Role deleted')
      fetchRoles()
    } catch (error) {
      message.error('Failed to delete role')
    }
  }

  const handleSubmit = async () => {
    try {
      const values = await form.validateFields()
      if (editingRole) {
        await rolesApi.update(editingRole.id, values)
        message.success('Role updated')
      } else {
        await rolesApi.create(values)
        message.success('Role created')
      }
      setModalOpen(false)
      fetchRoles()
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
      title: 'Description',
      dataIndex: 'description',
      key: 'description',
      ellipsis: true,
    },
    {
      title: 'Status',
      dataIndex: 'is_enabled',
      key: 'is_enabled',
      render: (enabled: boolean) =>
        enabled ? <Tag color="green">Enabled</Tag> : <Tag color="red">Disabled</Tag>,
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
      render: (_: any, record: Role) => (
        <Space>
          <Button icon={<EditOutlined />} onClick={() => handleEdit(record)} />
          <Popconfirm
            title="Delete this role?"
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
        <h2 className="page-title">Roles</h2>
        <Button type="primary" icon={<PlusOutlined />} onClick={handleCreate}>
          Add Role
        </Button>
      </div>

      <Table
        columns={columns}
        dataSource={roles}
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
        title={editingRole ? 'Edit Role' : 'Create Role'}
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
            label="Name"
            rules={[{ required: true }]}
          >
            <Input disabled={!!editingRole} />
          </Form.Item>
          <Form.Item
            name="display_name"
            label="Display Name"
            rules={[{ required: true }]}
          >
            <Input />
          </Form.Item>
          <Form.Item name="description" label="Description">
            <Input.TextArea rows={3} />
          </Form.Item>
          <Form.Item name="is_enabled" label="Enabled" valuePropName="checked">
            <Switch />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  )
}
