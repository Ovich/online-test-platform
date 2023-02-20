import {Box, Paper, Stack} from '@mui/material';
import ResizePanel from './utils/ResizePanel';

const LayoutSplitScreen = ({subheader, leftPanel, rightPanel, footer, rightWidth = 60, footerHeight = 0}) => {
    return (
        <>
        { subheader && (
            <Stack direction="row" alignItems="center" sx={{ minHeight:'52px', maxHeight:'52px', width:'100%' }}>{subheader}</Stack>
        )}
        <Stack sx={{ height: `calc(100% - ${subheader ? '52px' : '0px'} - ${footer ? `${footerHeight}px` : '0px'})`, minWidth:'100%' }} alignItems="center">
                <ResizePanel
                    rightWidth={rightWidth}
                    leftPanel={leftPanel}
                    rightPanel={
                        <Paper square elevation={0} sx={{ flex:1, position:'relative', overflow:'hidden', pt:2, pl:2, pb:1, height:'100%' }}>
                            {rightPanel}
                        </Paper>
                    }
                />
        </Stack>
        <Box sx={{ maxHeight: `${footerHeight}px`, height: `${footerHeight}px` }}>
            {footer}
        </Box>
       </>
    );
}


export default LayoutSplitScreen;
