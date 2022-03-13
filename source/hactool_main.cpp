/*
 * Copyright (c) Atmosphère-NX
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stratosphere.hpp>
#include "hactool_options.hpp"
#include "hactool_processor.hpp"

namespace ams {

    void Main() {
        /* Disable auto-abort when performing file operations. */
        fs::SetEnabledAutoAbort(false);

        /* Parse the options from command line. */
        auto options = hactool::ParseOptionsFromCommandLine();
        if (!options.valid) {
            hactool::PrintUsage();
            return;
        }

        /* Process. */
        if (const auto res = hactool::Processor(options).Process(); R_FAILED(res)) {
            fprintf(stderr, "[Warning]: tool failed to process input: 2%03d-%04d\n", res.GetModule(), res.GetDescription());
        }
    }

}