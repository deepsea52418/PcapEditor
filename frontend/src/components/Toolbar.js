// /home/tsn/PcapEditor/frontend/src/components/Toolbar.js
import React, { useState, useEffect } from 'react';
import { Button, Upload, Modal, Input, message } from 'antd';
import { UploadOutlined, SaveOutlined, UndoOutlined, RedoOutlined } from '@ant-design/icons';
import { savePcap, undo, redo } from '../api';

const Toolbar = ({ onUpload, filename, onUndoRedo }) => {
  const [isModalVisible, setIsModalVisible] = useState(false);
  const [newFilename, setNewFilename] = useState('');

  useEffect(() => {
    setNewFilename(filename);
  }, [filename]);

  const showModal = () => {
    setIsModalVisible(true);
  };

  const handleOk = async () => {
    if (!newFilename) {
      message.error('Filename cannot be empty.');
      return;
    }
    
    try {
      const response = await savePcap(newFilename);
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', newFilename);
      document.body.appendChild(link);
      link.click();
      link.remove();
      
      message.success(`File saved as ${newFilename}`);
      setIsModalVisible(false);
    } catch (error) {
      let errorMessage = 'Failed to save file.';
      if (error.response && error.response.data && error.response.data.error) {
        errorMessage = `Failed to save file: ${error.response.data.error}`;
      }
      message.error(errorMessage);
    }
  };

  const handleCancel = () => {
    setIsModalVisible(false);
  };

  const handleUndo = async () => {
    try {
      const response = await undo();
      onUndoRedo(response.data);
      message.success(response.data.message);
    } catch (error) {
      message.error(error.response?.data?.error || 'Failed to undo');
    }
  };

  const handleRedo = async () => {
    try {
      const response = await redo();
      onUndoRedo(response.data);
      message.success(response.data.message);
    } catch (error) {
      message.error(error.response?.data?.error || 'Failed to redo');
    }
  };

  const props = {
    name: 'file',
    accept: '.pcap,.pcapng',
    beforeUpload: (file) => {
      onUpload(file);
      return false; // Prevent antd from uploading automatically
    },
    showUploadList: false,
  };

  return (
    <div style={{ marginBottom: 16 }}>
      <Upload {...props}>
        <Button icon={<UploadOutlined />}>Upload Pcap</Button>
      </Upload>
      <Button
        icon={<SaveOutlined />}
        onClick={showModal}
        disabled={!filename}
        style={{ marginLeft: 8 }}
      >
        Save Pcap
      </Button>
      <Button icon={<UndoOutlined />} style={{ marginLeft: 8 }} onClick={handleUndo} disabled={!filename}>Undo</Button>
      <Button icon={<RedoOutlined />} style={{ marginLeft: 8 }} onClick={handleRedo} disabled={!filename}>Redo</Button>
      <Modal
        title="Save Pcap As"
        visible={isModalVisible}
        onOk={handleOk}
        onCancel={handleCancel}
      >
        <Input
          value={newFilename}
          onChange={(e) => setNewFilename(e.target.value)}
          placeholder="Enter filename"
        />
      </Modal>
    </div>
  );
};

export default Toolbar;
