import { Box, Button, Typography, useTheme } from '@mui/material';
import InlineMonacoEditor from './InlineMonacoEditor'
import ReactMarkdown from 'react-markdown'
import { Prism as SyntaxHighlighter } from "react-syntax-highlighter";
import copyToClipboard from 'clipboard-copy';
import { useSnackbar } from '../../context/SnackbarContext';
import { useCallback } from 'react';
/*
        using Monaco Editor for editing content in markdown
        using ReactMarkdown for displaying content in markdown
*/
const ContentEditor = ({
  readOnly = false,
  language = 'markdown',
  rawContent,
  onChange,
}) => {
  const theme = useTheme()

  const { show: showSnackbar } = useSnackbar()

  const handleCopyToClipboard = useCallback((code) => {
    copyToClipboard(code);
    // Optional: Show a notification or tooltip saying "Copied!"
    showSnackbar('Copied!', 'success')
  }, [showSnackbar])

  return readOnly ? (
    <ReactMarkdown
      components={{
        code: ({ children:code, className}) => {
          const language = className?.replace('language-', '') || 'text'
          return (
            <Box border={`1px dashed ${theme.palette.divider}`} borderRadius={1} mr={1} mt={1} mb={1} position={"relative"}>
              <SyntaxHighlighter language={language}>
                {code}
              </SyntaxHighlighter>
              <Button 
                  size="small"
                  sx={{ position: 'absolute', top: 0, right: 0 }}
                  onClick={() => handleCopyToClipboard(code)}
                >
                  Copy
              </Button>
            </Box>
          )
        },
      }}
    >{rawContent?.toString()}</ReactMarkdown>
  ) : (
    <InlineMonacoEditor
      minHeight={100}
      code={rawContent}
      language={language}
      readOnly={readOnly}
      onChange={onChange}
    />
  )
}

export default ContentEditor
