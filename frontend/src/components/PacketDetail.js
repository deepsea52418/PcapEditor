// /home/tsn/PcapEditor/frontend/src/components/PacketDetail.js
import React, { useState, useEffect } from 'react';
import { Tree, Col, Row, Spin, Empty, Input, Tooltip } from 'antd';
import SimpleHexEditor from './SimpleHexEditor';
import { updatePacket, updatePacketTimestamp } from '../api';
import { debounce } from 'lodash';

const EditableNode = ({ node, packetId, onDetailChange }) => {
  const [value, setValue] = useState(node.value);

  // Sync local state with parent prop when a new packet is selected
  useEffect(() => {
    setValue(node.value);
  }, [node.value]);

  // Update local state on every keystroke
  const handleChange = (e) => {
    setValue(e.target.value);
  };

  // Function to send the update to the backend
  const handleUpdate = async () => {
    const newTimestamp = parseFloat(value);
    if (isNaN(newTimestamp)) {
      console.error("Invalid timestamp format. Reverting.");
      // Revert to the original value if input is invalid
      setValue(node.value);
      return;
    }

    // Avoid sending an update if the value hasn't changed
    if (newTimestamp === parseFloat(node.value)) {
      return;
    }

    try {
      const response = await updatePacketTimestamp(packetId, newTimestamp);
      onDetailChange(response.data);
    } catch (error) {
      console.error("Failed to update timestamp", error);
      // Revert to original value on error
      setValue(node.value);
    }
  };

  if (node.is_editable) {
    return (
      <span onClick={(e) => e.stopPropagation()}>
        {node.title.split(':')[0]}:{' '}
        <Tooltip title="Press Enter or click away to save">
          <Input 
            value={value}
            onChange={handleChange}
            onBlur={handleUpdate} // Update when input loses focus
            onPressEnter={handleUpdate} // Update when Enter is pressed
            style={{ width: 'auto', display: 'inline-block' }}
            size="small"
          />
        </Tooltip>
      </span>
    );
  }
  return node.title;
};


const PacketDetail = ({ packet, detail, onDetailChange }) => {
  const [highlight, setHighlight] = useState({ start: -1, end: -1 });
  const [currentHex, setCurrentHex] = useState('');

  useEffect(() => {
    if (detail) {
      setCurrentHex(detail.hex);
      // Check if there's a highlight range to apply on load
      if (detail.highlight_range_on_load) {
        const [start, end] = detail.highlight_range_on_load;
        setHighlight({ start, end });
      } else {
        // Clear highlight if no specific range is provided
        setHighlight({ start: -1, end: -1 });
      }
    } else {
      setCurrentHex('');
      setHighlight({ start: -1, end: -1 });
    }
  }, [detail]);

  if (!packet) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%', background: '#fff' }}>
        <Empty description="Select a packet to see details" />
      </div>
    );
  }

  if (!detail) {
    return <Spin tip="Loading packet details..." />;
  }

  const hexStringToBuffer = (hexString) => {
    if (!hexString || hexString.length === 0) {
      return new ArrayBuffer(0);
    }
    const bytes = [];
    for (let i = 0; i < hexString.length; i += 2) {
      bytes.push(parseInt(hexString.substr(i, 2), 16));
    }
    return new Uint8Array(bytes).buffer;
  };

  const handleHexChange = debounce(async (newHexString) => {
    try {
      const response = await updatePacket(packet.id, newHexString);
      onDetailChange(response.data);
      // No message here to avoid being too noisy
    } catch (error) {
      // Silently fail or add a subtle indicator
    }
  }, 300);

  const handleNodeSelect = (selectedKeys, { node }) => {
    if (node.byteRange) {
      const [start, end] = node.byteRange;
      setHighlight({ start, end });
    } else {
      setHighlight({ start: -1, end: -1 });
    }
  };

  const onHexEditorChange = (newHex) => {
    setCurrentHex(newHex);
    handleHexChange(newHex);
  };

  const renderTitle = (node) => {
    if (node.is_editable) {
      return <EditableNode node={node} packetId={packet.id} onDetailChange={onDetailChange} />;
    }
    return node.title;
  };

  return (
    <Row style={{ height: '100%', flexWrap: 'nowrap' }}>
      <Col span={12} style={{ height: '100%', overflow: 'auto', borderRight: '1px solid #f0f0f0', paddingRight: '8px' }}>
        <Tree
          showLine
          defaultExpandAll
          treeData={detail.layers}
          onSelect={handleNodeSelect}
          titleRender={renderTitle}
        />
      </Col>
      <Col span={12} style={{ height: '100%', overflow: 'auto', paddingLeft: '8px' }}>
        <SimpleHexEditor
          data={hexStringToBuffer(currentHex)}
          onHexChange={onHexEditorChange}
          highlight={highlight}
        />
      </Col>
    </Row>
  );
};

export default PacketDetail;





