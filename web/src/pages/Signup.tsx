import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Form, Input, Button, message } from 'antd'
import { UserOutlined, LockOutlined, HomeOutlined, MailOutlined } from '@ant-design/icons'
import { useAuth } from '../context/AuthContext'

export default function Signup() {
  const [loading, setLoading] = useState(false)
  const { signup } = useAuth()
  const navigate = useNavigate()

  const onFinish = async (values: {
    owner: string
    name: string
    password: string
    display_name: string
    email?: string
  }) => {
    setLoading(true)
    try {
      await signup(values)
      message.success('Signup successful!')
      navigate('/')
    } catch (error: any) {
      message.error(error.response?.data?.message || 'Signup failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-container">
      <div className="login-card">
        <div className="login-title">
          <div className="login-logo">🔐</div>
          <h1>Casdog</h1>
          <p style={{ color: '#666' }}>Create your account</p>
        </div>
        <Form
          name="signup"
          initialValues={{ owner: 'built-in' }}
          onFinish={onFinish}
          size="large"
        >
          <Form.Item
            name="owner"
            rules={[{ required: true, message: 'Please input organization!' }]}
          >
            <Input prefix={<HomeOutlined />} placeholder="Organization" />
          </Form.Item>
          <Form.Item
            name="name"
            rules={[{ required: true, message: 'Please input username!' }]}
          >
            <Input prefix={<UserOutlined />} placeholder="Username" />
          </Form.Item>
          <Form.Item
            name="display_name"
            rules={[{ required: true, message: 'Please input display name!' }]}
          >
            <Input prefix={<UserOutlined />} placeholder="Display Name" />
          </Form.Item>
          <Form.Item name="email">
            <Input prefix={<MailOutlined />} placeholder="Email (optional)" />
          </Form.Item>
          <Form.Item
            name="password"
            rules={[
              { required: true, message: 'Please input password!' },
              { min: 6, message: 'Password must be at least 6 characters!' },
            ]}
          >
            <Input.Password prefix={<LockOutlined />} placeholder="Password" />
          </Form.Item>
          <Form.Item
            name="confirm"
            dependencies={['password']}
            rules={[
              { required: true, message: 'Please confirm password!' },
              ({ getFieldValue }) => ({
                validator(_, value) {
                  if (!value || getFieldValue('password') === value) {
                    return Promise.resolve()
                  }
                  return Promise.reject(new Error('Passwords do not match!'))
                },
              }),
            ]}
          >
            <Input.Password prefix={<LockOutlined />} placeholder="Confirm Password" />
          </Form.Item>
          <Form.Item>
            <Button type="primary" htmlType="submit" loading={loading} block>
              Sign up
            </Button>
          </Form.Item>
          <div style={{ textAlign: 'center' }}>
            Already have an account? <Link to="/login">Log in</Link>
          </div>
        </Form>
      </div>
    </div>
  )
}
