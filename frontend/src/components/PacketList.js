// /home/tsn/PcapEditor/frontend/src/components/PacketList.j
import { Table, Button, Popconfirm, message } from 'antd';
import { DeleteOutlined } from '@ant-design/icons';
import { deletePacket } from '../api';

const PacketList = ({ packets, onSelectPacket, selectedPacketId, onSort, onPacketsChange }) => {

  const handleDelete = async (packetId) => {
    try {
      const response = await deletePacket(packetId);
      onPacketsChange(response.data.packets);
      message.success(response.data.message);
    } catch (error) {
      message.error('Failed to delete packet');
    }
  };

  const columns = [
    {
      title: 'ID',
      dataIndex: 'id',
      key: 'id',
      sorter: true,
    },
    {
      title: 'Timestamp',
      dataIndex: 'timestamp',
      key: 'timestamp',
      sorter: true,
    },
    {
      title: 'Source',
      dataIndex: 'src',
      key: 'src',
      sorter: true,
    },
    {
      title: 'Destination',
      dataIndex: 'dst',
      key: 'dst',
      sorter: true,
    },
    {
      title: 'Protocol',
      dataIndex: 'proto',
      key: 'proto',
      sorter: true,
    },
    {
      title: 'Length',
      dataIndex: 'len',
      key: 'len',
      sorter: true,
    },
    {
      title: 'Vlan ID',
      dataIndex: 'vlan_id',
      key: 'vlan_id',
      sorter: true,
    },
    {
      title: 'Info',
      dataIndex: 'info',
      key: 'info',
      sorter: true,
    },
    {
      title: 'Action',
      key: 'action',
      render: (_, record) => (
        <Popconfirm
          title="Are you sure to delete this packet?"
          onConfirm={() => handleDelete(record.id)}
          okText="Yes"
          cancelText="No"
        >
          <Button icon={<DeleteOutlined />} danger size="small" />
        </Popconfirm>
      ),
    },
  ];

  return (
    <Table
      columns={columns}
      dataSource={packets}
      rowKey="id"
      size="small"
      pagination={{ pageSize: 50, showSizeChanger: false }}
      onRow={(record) => ({
        onClick: () => onSelectPacket(record),
      })}
      rowClassName={(record) =>
        record.id === selectedPacketId ? 'ant-table-row-selected' : ''
      }
      onChange={onSort}
    />
  );
};

export default PacketList;
