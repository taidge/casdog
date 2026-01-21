import { useEffect, useState } from 'react'
import {
  Table,
  Button,
  Space,
  Modal,
  Form,
  Input,
  Select,
  Switch,
  message,
  Popconfirm,
  Tag,
} from 'antd'
import { PlusOutlined, EditOutlined, DeleteOutlined } from '@ant-design/icons'
import { permissionsApi, Permission } from '../api/client'

export default function Permissions() {
  const [loading, setLoading] = useState(false)
  const [permissions, setPermissions] = useState<Permission[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(10)
  const [modalOpen, setModalOpen] = useState(false)
  const [editingPermission, setEditingPermission] = useState<Permission | null>(null)
  const [form] = Form.useForm()

  const fetchPermissions = async () => {
    setLoading(true)
    try {
      const res = await permissionsApi.list({ page, page_size: pageSize })
      setPermissions(res.data.data)
      setTotal(res.data.total)
    } catch (error) {
      message.error('Failed to fetch permissions')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchPermissions()
  }, [page, pageSize])

  const handleCreate = () => {
    setEditingPermission(null)
    form.resetFields()
    form.setFieldsValue({
      owner: 'built-in',
      effect: 'allow',
      is_enabled: true,
    })
    setModalOpen(true)
  }

  const handleEdit = (permission: Permission) => {
    setEditingPermission(permission)
    form.setFieldsValue(permission)
    setModalOpen(true)
  }

  const handleDelete = async (id: string) => {
    try {
      await permissionsApi.delete(id)
      message.success('Permission deleted')
      fetchPermissions()
    } catch (error) {
      message.error('Failed to delete permission')
    }
  }

  const handleSubmit = async () => {
    try {
      const values = await form.validateFields()
      if (editingPermission) {
        await permissionsApi.update(editingPermission.id, values)
        message.success('Permission updated')
      } else {
        await permissionsApi.create(values)
        message.success('Permission created')
      }
      setModalOpen(false)
      fetchPermissions()
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
      title: 'Resource Type',
      dataIndex: 'resource_type',
      key: 'resource_type',
    },
    {
      title: 'Resources',
      dataIndex: 'resources',
      key: 'resources',
      ellipsis: true,
    },
    {
      title: 'Actions',
      dataIndex: 'actions',
      key: 'actions',
    },
    {
      title: 'Effect',
      dataIndex: 'effect',
      key: 'effect',
      render: (effect: string) =>
        effect === 'allow' ? (
          <Tag color="green">Allow</Tag>
        ) : (
          <Tag color="red">Deny</Tag>
        ),
    },
    {
      title: 'Status',
      dataIndex: 'is_enabled',
      key: 'is_enabled',
      render: (enabled: boolean) =>
        enabled ? <Tag color="green">Enabled</Tag> : <Tag color="red">Disabled</Tag>,
    },
    {
      title: 'Actions',
      key: 'action_buttons',
      render: (_: any, record: Permission) => (
        <Space>
          <Button icon={<EditOutlined />} onClick={() => handleEdit(record)} />
          <Popconfirm
            title="Delete this permission?"
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
        <h2 className="page-title">Permissions</h2>
        <Button type="primary" icon={<PlusOutlined />} onClick={handleCreate}>
          Add Permission
        </Button>
      </div>

      <Table
        columns={columns}
        dataSource={permissions}
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
        title={editingPermission ? 'Edit Permission' : 'Create Permission'}
        open={modalOpen}
        onOk={handleSubmit}
        onCancel={() => setModalOpen(false)}
        width={600}
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
            <Input disabled={!!editingPermission} />
          </Form.Item>
          <Form.Item
            name="display_name"
            label="Display Name"
            rules={[{ required: true }]}
          >
            <Input />
          </Form.Item>
          <Form.Item name="description" label="Description">
            <Input.TextArea rows={2} />
          </Form.Item>
          <Form.Item
            name="resource_type"
            label="Resource Type"
            rules={[{ required: true }]}
          >
            <Input placeholder="e.g., api, page, menu" />
          </Form.Item>
          <Form.Item
            name="resources"
            label="Resources"
            rules={[{ required: true }]}
          >
            <Input.TextArea
              rows={2}
              placeholder="e.g., /api/users, /api/roles/*"
            />
          </Form.Item>
          <Form.Item
            name="actions"
            label="Actions"
            rules={[{ required: true }]}
          >
            <Input placeholder="e.g., read, write, delete, *" />
          </Form.Item>
          <Form.Item name="effect" label="Effect">
            <Select>
              <Select.Option value="allow">Allow</Select.Option>
              <Select.Option value="deny">Deny</Select.Option>
            </Select>
          </Form.Item>
          <Form.Item name="is_enabled" label="Enabled" valuePropName="checked">
            <Switch />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  )
}
