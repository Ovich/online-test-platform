import { Box, Stack } from '@mui/material'

import Header from './Header'
import ScrollContainer from './ScrollContainer'
const LayoutMain = ({
  children,
  header,
  subheader,
  padding = 0,
  spacing = 0,
}) => {
  return (
    <>
      <Stack height={'100vh'} width={'100vw'}>
        <Header color="transparent"> {header} </Header>
        {subheader && <Box sx={{ overflow: 'hidden' }}>{subheader}</Box>}
        <ScrollContainer padding={padding} spacing={spacing}>
          {children}
        </ScrollContainer>
      </Stack>
    </>
  )
}

export default LayoutMain
